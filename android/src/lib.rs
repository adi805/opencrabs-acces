// OpenCrabs Android GUI (full Rust: egui/eframe + GameActivity).
//
// Constraint yang gak boleh regression (semua pernah dibayar dengan run CI
// merah, jangan pangkas komentar ini):
//   * Glue wajib game-activity: native_activity punya text_input_state() NOP
//     (android-activity 0.6.0 native_activity/mod.rs:381, :390) -> IME mati.
//   * android-activity terkunci =0.6.0 + vendor null-guard: 0.6.1 bawa
//     onTouchEventNative 17-arg yang pecahin RegisterNatives terhadap AAR
//     games-activity 2.0.2 (SIGABRT saat load, run 45593951071).
//   * Panic di-route ke logcat tag OcGui lewat hook di bawah (stderr Android
//     tidak kelihatan di diagnostics CI).
mod app;
mod ime;
mod mock;

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: winit::platform::android::activity::AndroidApp) {
    use crate::{app::ChatApp, ime::ImeBridge};

    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("OcGui"),
    );
    // stderr tidak ke-logcat: tiap panic wajib muncul di tag OcGui.
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        log::error!("PANIC at {} : {}", loc, info.to_string());
    }));
    log::info!("APP_START glue=game-activity");

    let options = eframe::NativeOptions {
        android_app: Some(app.clone()),
        ..Default::default()
    };

    eframe::run_native(
        "OpenCrabs GUI",
        options,
        Box::new(|_cc| Ok(Box::new(ChatApp::new_android(ImeBridge::new(app))))),
    )
    .expect("eframe::run_native failed");
}
