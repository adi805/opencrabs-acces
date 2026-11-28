#!/usr/bin/env bash
# Emulator self-test untuk OpenCrabs Android GUI (scaffold UI asli, bukan
# TextEdit demo lagi).
#
# ALUR YANG DIBUKTIKAN
#   1. App hidup: UI_READY ke-log dari ChatApp.
#   2. Tap composer (koordinat dari log COMPOSER, bukan tebakan) -> IME
#      window muncul.
#   3. Teks "rekap penjualan" masuk lewat jalur IME asli
#      (ADBKeyboard commitText -> GameTextInput -> text_input_state ->
#      IME_ADOPT -> COMPOSER_TEXT). App cuma pernah baca
#      text_input_state(), jadi COMPOSER_TEXT hanya bisa datang dari bridge.
#   4. Tap tombol Kirim (koordinat log SEND) -> SENT_TO_AGENT ->
#      MOCK_STREAM_START -> MOCK_STREAM_DONE tokens>0: transcript streaming
#      dari state, bukan teks optimistis.
#
# TIDAK DIBUKTIKAN DI SINI
#   Gboard/autokorekt, hardware keyboard, koneksi core opencrabs (task 3).
#
# KENAPA FILE TERPISAH
#   reactivecircus/android-emulator-runner@v2 memecah `script:` per baris jadi
#   `sh -c` terpisah (lib/script-parser.js + lib/main.js:212-215): variabel
#   shell mati antar baris dan blok multi-baris terhambat. Workflow memanggil
#   persis satu baris: `bash ci/selftest.sh`.
#
# KENAPA ADBKEYBOARD
#   `adb shell input text` injek raw KeyEvent yang AGDK rutekan ke
#   onKeyDownNative dan tidak pernah menyentuh text state. ADBKeyboard
#   (senzhk/ADBKeyBoard, MIT) adalah InputMethodService sungguhan yang commit
#   lewat InputConnection.commitText(): jalur yang sama dengan keyboard HP.

set -u
set -o pipefail

ADB="${ADB:-adb}"
ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
APK="${APK:-$ROOT/app/build/outputs/apk/debug/app-debug.apk}"
ADBKEYBOARD_APK="${ADBKEYBOARD_APK:-$ROOT/ci/ADBKeyboard.apk}"
PKG="io.opencrabs.mobile.gui"
ACTIVITY="$PKG/.MainActivity"
IME_ID="com.android.adbkeyboard/.AdbIME"
TEXT_TO_TYPE="rekap penjualan"

say() { echo "[selftest] $*"; }

shot() {
  local name="$1"
  $ADB shell screencap -p "/sdcard/$name" >/dev/null 2>&1 || return 0
  $ADB pull "/sdcard/$name" "$ROOT/$name" >/dev/null 2>&1 || true
  say "screenshot: $ROOT/$name"
}

diag() {
  say "===== DIAGNOSTICS ====="
  echo "--- adb devices ---"; $ADB devices -l 2>&1 || true
  echo "--- wm size / density ---"; $ADB shell wm size 2>&1; $ADB shell wm density 2>&1
  echo "--- ime list -s ---"; $ADB shell ime list -s 2>&1 || true
  echo "--- dumpsys input_method (key fields) ---"
  $ADB shell dumpsys input_method 2>&1 | grep -E 'mCurMethodId|mInputShown|mInputViewShown|mCurFocusedWindow' || true
  echo "--- app log (OcGui) ---"
  $ADB logcat -d -s OcGui 2>&1 | tail -80 || true
  echo "--- rust stderr (RustStdoutStderr) ---"
  $ADB logcat -d -s RustStdoutStderr 2>&1 | tail -40 || true
  $ADB logcat -d 2>&1 > "$ROOT/logcat-full.log" || true
  $ADB logcat -d -b crash 2>&1 > "$ROOT/crash-buffer.log" || true
  echo "--- logcat -b crash: abort message + top frames (HEAD) ---"
  grep -aE 'Abort message|Fatal signal|signal [0-9]|>>> |^Cause' "$ROOT/crash-buffer.log" 2>/dev/null | head -12 || true
  grep -aE '^\s+#([0-9]|[1-3][0-9]) pc' "$ROOT/crash-buffer.log" 2>/dev/null | head -32 || true
  echo "--- logcat: fatal / exception ---"
  $ADB logcat -d 2>&1 | grep -aE 'FATAL EXCEPTION|E AndroidRuntime|UnsatisfiedLink|NoSuchMethod|RegisterNatives|JNI DETECTED|PANIC' | head -30 || true
  echo "--- dumpsys package io.opencrabs.mobile.gui ---"
  $ADB shell dumpsys package "$PKG" 2>&1 | grep -aE 'nativeLibraryDir|primaryCpuAbi|versionName' | head -6 || true
  echo "===== END DIAGNOSTICS ====="
}

fail() {
  say "SELFTEST-FAIL: $*"
  shot "fail-selftest.png"
  diag
  exit 1
}

log_line() { # $1 = regex, echo baris terakhir yang cocok
  $ADB logcat -d -s OcGui 2>/dev/null | grep -E "$1" | tail -1
}

wait_log() { # $1 = regex, $2 = max polls
  local n=0
  while [ "$n" -lt "$2" ]; do
    if $ADB logcat -d -s OcGui 2>/dev/null | grep -qE "$1"; then return 0; fi
    n=$((n+1)); sleep 5
  done
  return 1
}

tap_from_log() { # $1 = tag log (COMPOSER/SEND), set X Y global
  local line tag="$1"
  line=$(log_line "$tag pxcx=[0-9]")
  say "$tag line: ${line:-<none>}"
  TAPX=$(echo "$line" | sed -n "s/.*pxcx=\([0-9]*\).*/\1/p")
  TAPY=$(echo "$line" | sed -n "s/.*pxcy=\([0-9]*\).*/\1/p")
  case "$TAPX" in ''|*[!0-9]*) return 1;; esac
  case "$TAPY" in ''|*[!0-9]*) return 1;; esac
  [ "$TAPX" -gt 0 ] && [ "$TAPY" -gt 0 ] || return 1
  return 0
}

say "cwd: $(pwd)"
say "APK: $APK"
[ -f "$APK" ] || fail "APK not found: $APK"
say "APK native libs:"; unzip -l "$APK" 2>/dev/null | grep -aE 'lib/.*\.so' | head -10 || true
[ -f "$ADBKEYBOARD_APK" ] || fail "ADBKeyboard APK not found: $ADBKEYBOARD_APK"

$ADB wait-for-device || fail "adb: no device"

BOOTED=0
for _ in $(seq 1 60); do
  if [ "$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
    BOOTED=1; break
  fi
  sleep 5
done
[ "$BOOTED" = "1" ] || fail "emulator never finished booting"
say "device booted"

say "installing app APK"
$ADB install -r "$APK" 2>&1 | tail -3 || fail "adb install app failed"

say "installing ADBKeyboard IME"
$ADB install -r "$ADBKEYBOARD_APK" 2>&1 | tail -3 || fail "adb install ADBKeyboard failed"

# IME baru terinstall tidak muncul di `ime list -s` (hanya ENABLED): poll
# `ime list -s -a` untuk REGISTRASI dulu, baru enable + set.
say "waiting for ADBKeyboard to register: $IME_ID"
IME_SEEN=0
for _ in $(seq 1 60); do
  if $ADB shell ime list -s -a 2>/dev/null | grep -q "^${IME_ID}$"; then IME_SEEN=1; break; fi
  sleep 10
done
[ "$IME_SEEN" = "1" ] || { $ADB shell ime list -s -a; fail "ADBKeyboard never appeared in ime list -s -a"; }
say "selecting IME: $IME_ID"
$ADB shell ime enable "$IME_ID" 2>&1 | tail -1 || fail "ime enable failed"
$ADB shell ime set "$IME_ID" 2>&1 | tail -1 || fail "ime set failed"
$ADB shell dumpsys input_method 2>/dev/null | grep -q "mCurMethodId=${IME_ID}" || fail "ime set did not take effect"
# Emulator punya hw keyboard; tanpa ini IME window disembunyikan.
$ADB shell settings put secure show_ime_with_hard_keyboard 1 2>&1 || true

$ADB logcat -c
say "starting $ACTIVITY"
$ADB shell am start -W -n "$ACTIVITY" 2>&1 | tail -5 || fail "am start failed"

# 1. App hidup + scaffold terpasang.
say "waiting for UI_READY"
wait_log 'UI_READY sessions=[0-9]' 36 || fail "app never logged UI_READY"
$ADB logcat -d -s OcGui | grep -E 'APP_START|APP_READY|UI_READY|COMPOSER|SEND' | tail -10

# 2. Tap composer -> keyboard muncul.
tap_from_log COMPOSER || fail "no valid COMPOSER coords in log"
say "tapping composer at $TAPX x $TAPY"
$ADB shell input tap "$TAPX" "$TAPY"
ime_shown() {
  $ADB shell dumpsys input_method 2>/dev/null | grep -qE 'mInputShown=true|mInputViewShown=true' && return 0
  $ADB shell dumpsys window 2>/dev/null | grep -qE 'mImeWindowVis=0x2' && return 0
  return 1
}
KB=0
for _ in $(seq 1 24); do
  if ime_shown; then KB=1; break; fi
  sleep 5
done
[ "$KB" = "1" ] || fail "IME window never showed after composer tap"
say "KEYBOARD SHOWN"
shot "keyboard-shown.png"

# 3. Ketik lewat jalur IME (commitText): retry aman karena state di-set penuh.
say "sending text via IME commit: $TEXT_TO_TYPE"
TYPED=0
for attempt in 1 2 3 4 5 6; do
  # Eksplisit ke komponen: implicit broadcast di API 34+ di-rute salah
  # (bukti run 46074165538: "Broadcasting: Intent { act=ADB_INPUT_TEXT pkg=penjualan }")
  $ADB shell am broadcast -a ADB_INPUT_TEXT --es msg "$TEXT_TO_TYPE" com.android.adbkeyboard/.AdbIME 2>&1 | tail -2 || true
  for _ in $(seq 1 8); do
    if $ADB logcat -d -s OcGui 2>/dev/null | grep -qE 'COMPOSER_TEXT chars=[1-9]'; then TYPED=1; break; fi
    sleep 5
  done
  [ "$TYPED" = "1" ] && break
  say "attempt $attempt: composer still empty, retrying"
done
[ "$TYPED" = "1" ] || fail "typed text never reached the composer (IME bridge broken)"
say "TEXT REACHED COMPOSER"

# 4. Tap Kirim -> transcript streaming dari state.
tap_from_log SEND || fail "no valid SEND coords in log"
say "tapping Kirim at $TAPX x $TAPY"
$ADB shell input tap "$TAPX" "$TAPY"
wait_log 'SENT_TO_AGENT' 12 || fail "Send tap did not reach the agent"
wait_log 'MOCK_STREAM_DONE tokens=[1-9]' 60 || fail "mock reply never finished streaming"
say "MOCK REPLY STREAMED (state -> transcript)"

$ADB logcat -d -s OcGui | grep -E 'IME_TEXT|IME_ADOPT|COMPOSER_TEXT|SENT_TO_AGENT|MOCK_STREAM|IME_REQUEST' | tail -30
shot "pass.png"
say "SELFTEST PASS: UI up + keyboard + IME text + send + streamed reply"
