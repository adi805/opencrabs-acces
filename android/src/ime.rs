// IME bridge, isolated so app.rs stays target-independent.
//
// Constraint yang gak boleh regression:
//   * Glue wajib game-activity. native_activity punya text_input_state() yang
//     selalu kosong + set_text_input_state() NOP
//     (android-activity 0.6.0 native_activity/mod.rs:381 dan :390).
//   * Push-back (set_text_input_state) HANYA buat edit programatik:
//     AGDK InputConnection.setState() menimpa seluruh editable, jadi push
//     tiap frame = ngehapus karakter yang baru di-commit IME.
#[cfg(target_os = "android")]
mod imp {
    use winit::platform::android::activity::input::{TextSpan, TextInputState};
    use winit::platform::android::activity::AndroidApp;

    pub struct ImeBridge {
        app: AndroidApp,
        ime_text: String,
        pending_push: Option<String>,
        ime_calls: u32,
        next_ime_at: f64,
    }

    impl ImeBridge {
        pub fn new(app: AndroidApp) -> Self {
            Self {
                app,
                ime_text: String::new(),
                pending_push: None,
                ime_calls: 0,
                next_ime_at: 0.0,
            }
        }

        /// Poll state IME dan adopsi teks yang di-commit ke composer.
        /// Returns true kalau composer berubah.
        pub fn sync(&mut self, composer: &mut String) -> bool {
            let ts = self.app.text_input_state();
            if ts.text != self.ime_text {
                log::info!(
                    "IME_TEXT chars={} text={:?} sel={}..{}",
                    ts.text.chars().count(),
                    ts.text,
                    ts.selection.start,
                    ts.selection.end
                );
                self.ime_text = ts.text.clone();
            }
            match &self.pending_push {
                Some(expected) => {
                    if *expected == self.ime_text {
                        self.pending_push = None;
                    }
                    false
                }
                None => {
                    if self.ime_text != *composer {
                        log::info!("IME_ADOPT chars={}", self.ime_text.chars().count());
                        *composer = self.ime_text.clone();
                        true
                    } else {
                        false
                    }
                }
            }
        }

        /// Penggantian programatik (tombol Kirim mengosongkan composer).
        pub fn replace(&mut self, composer: &mut String, text: &str) {
            let len = text.len();
            self.app.set_text_input_state(TextInputState {
                text: text.to_string(),
                selection: TextSpan {
                    start: len,
                    end: len,
                },
                compose_region: None,
            });
            self.pending_push = Some(text.to_string());
            *composer = text.to_string();
            log::info!("IME_PUSH chars={}", text.chars().count());
        }

        /// Minta keyboard di edge fokus. AGDK setSoftKeyboardActive(true)
        /// memanggil restartInput(), jadi tidak boleh tiap frame; retry
        /// beberapa kali dengan jeda.
        pub fn request_keyboard(&mut self, focused: bool, now: f64) {
            if focused
                && (self.ime_calls == 0
                    || (self.ime_calls < 6 && now >= self.next_ime_at))
            {
                self.app.show_soft_input(true);
                self.ime_calls += 1;
                self.next_ime_at = now + 1.5;
                log::info!("IME_REQUEST n={}", self.ime_calls);
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    pub struct ImeBridge;

    impl ImeBridge {
        pub fn new() -> Self {
            ImeBridge
        }

        pub fn sync(&mut self, _composer: &mut String) -> bool {
            false
        }

        pub fn replace(&mut self, composer: &mut String, text: &str) {
            *composer = text.to_string();
        }

        pub fn request_keyboard(&mut self, _focused: bool, _now: f64) {}
    }
}

pub use imp::ImeBridge;
