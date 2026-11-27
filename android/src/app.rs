// OpenCrabs Android GUI scaffold: sesi + transcript chat + aktivitas tool +
// status. Layout mobile (touch-friendly, dark theme), dan CI evidence hooks
// lewat tag log OcGui.
use crate::ime::ImeBridge;
use crate::mock::MockAgent;
use eframe::egui;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    User,
    Agent,
    Tool,
}

#[derive(Clone, Debug)]
pub struct Msg {
    pub role: Role,
    pub text: String,
    pub streaming: bool,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub title: String,
    pub msgs: Vec<Msg>,
}

#[derive(Clone, Debug)]
pub struct ToolEvent {
    pub label: String,
    pub ok: bool,
}

pub struct ChatApp {
    pub sessions: Vec<Session>,
    pub active: usize,
    pub drawer_open: bool,
    pub composer: String,
    pub tools: Vec<ToolEvent>,
    pub connected: bool,
    agent: MockAgent,
    ime: ImeBridge,
    focus_requested: bool,
    frame: u64,
    last_composer_px: (i32, i32),
    send_logged: bool,
    last_composer_chars: usize,
}

impl ChatApp {
    #[cfg(target_os = "android")]
    pub fn new_android(ime: ImeBridge) -> Self {
        Self::build(ime)
    }

    #[cfg(not(target_os = "android"))]
    pub fn new() -> Self {
        Self::build(ImeBridge::new())
    }

    fn build(ime: ImeBridge) -> Self {
        Self {
            sessions: seed_sessions(),
            active: 0,
            drawer_open: false,
            composer: String::new(),
            tools: seed_tools(),
            connected: true,
            agent: MockAgent::new(),
            ime,
            focus_requested: false,
            frame: 0,
            last_composer_px: (-1, -1),
            send_logged: false,
            last_composer_chars: usize::MAX,
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.frame += 1;
        let now = ui.input(|i| i.time);

        // IME state dibaca tiap frame selama composer hidup.
        self.ime.sync(&mut self.composer);

        // Urutan panel WAJIB: top/bottom/side dulu, CentralPanel PALING AKHIR.
        // CentralPanel mengambil seluruh rect yang tersisa; kalau dia dipanggil
        // sebelum Panel::bottom, composer ditaruh DI LUAR layar (bukti run
        // 46017121968: COMPOSER pxcy=703 padahal screen=320x640), tap selftest
        // mendarat di kosong, keyboard nggak pernah muncul.
        if self.frame == 1 {
            let r = ui.ctx().content_rect();
            log::info!(
                "SCREEN {}x{} ppp={}",
                r.width(),
                r.height(),
                ui.ctx().pixels_per_point()
            );
        }
        self.top_bar(ui);
        self.composer_bar(ui, now);
        self.drawer(ui);
        self.transcript(ui);

        if let Some(tokens) = self.agent.tick(&mut self.sessions, self.active, now) {
            log::info!("MOCK_STREAM_DONE tokens={}", tokens);
        }

        let interval = if self.agent.is_streaming() { 80 } else { 250 };
        ui.ctx()
            .request_repaint_after(Duration::from_millis(interval));
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("oc_topbar")
            .frame(egui::Frame::default().inner_margin(egui::Margin::symmetric(12, 8)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.add_sized([42.0, 34.0], egui::Button::new("☰")).clicked() {
                        self.drawer_open = !self.drawer_open;
                    }
                    let title = self.sessions[self.active].title.clone();
                    ui.heading(title);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let dot = if self.connected { "🟢" } else { "🔴" };
                        let label = if self.connected { "mock" } else { "offline" };
                        ui.label(format!("{} {}", dot, label));
                    });
                });
            });
    }

    fn drawer(&mut self, ui: &mut egui::Ui) {
        if !self.drawer_open {
            return;
        }
        egui::Panel::left("oc_sessions")
            .exact_size(210.0)
            .frame(egui::Frame::default().inner_margin(egui::Margin::symmetric(10, 10)))
            .show_inside(ui, |ui| {
                ui.label(egui::RichText::new("SESI").strong());
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, s) in self.sessions.clone().iter().enumerate() {
                        let label = format!("{}\n{} pesan", s.title, s.msgs.len());
                        let sel = ui.selectable_label(i == self.active, label);
                        if sel.clicked() && i != self.active {
                            self.active = i;
                            self.drawer_open = false;
                            log::info!("SWITCH_SESSION id={}", s.id);
                        }
                    }
                });
            });
    }

    fn transcript(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(egui::Frame::default().inner_margin(egui::Margin::symmetric(10, 8)))
            .show_inside(ui, |ui| {
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let msgs = self.sessions[self.active].msgs.clone();
                        for m in &msgs {
                            match m.role {
                                Role::User => {
                                    let body = if m.text.is_empty() { "…" } else { &m.text };
                                    ui.label(
                                        egui::RichText::new(format!("LO ▸ {}", body))
                                            .color(egui::Color32::from_rgb(0x9e, 0xc5, 0xff))
                                            .strong(),
                                    );
                                }
                                Role::Agent => {
                                    let cursor = if m.streaming { " ▌" } else { "" };
                                    ui.label(egui::RichText::new(format!(
                                        "CRAB ▸ {}{}",
                                        m.text, cursor
                                    )));
                                }
                                Role::Tool => {
                                    ui.label(
                                        egui::RichText::new(format!("TOOL ▸ {}", m.text))
                                            .monospace()
                                            .small()
                                            .weak(),
                                    );
                                }
                            }
                            ui.add_space(6.0);
                        }
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Tool:").weak());
                    let tools = self.tools.clone();
                    for t in tools.iter().rev().take(3) {
                        let mark = if t.ok { "✔" } else { "✘" };
                        ui.label(
                            egui::RichText::new(format!("{} {}", mark, t.label))
                                .monospace()
                                .small(),
                        );
                    }
                });
            });
    }

    fn composer_bar(&mut self, ui: &mut egui::Ui, now: f64) {
        egui::Panel::bottom("oc_composer")
            .frame(egui::Frame::default().inner_margin(egui::Margin::symmetric(10, 8)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    let edit_w = ui.available_width() - 92.0;
                    let edit = egui::TextEdit::singleline(&mut self.composer)
                        .hint_text("ketik pesan…")
                        .desired_width(edit_w);
                    let out = ui.add_sized([edit_w, 42.0], edit);
                    if !self.focus_requested {
                        out.request_focus();
                        self.focus_requested = true;
                    }
                    self.ime.request_keyboard(out.has_focus(), now);

                    let ppp = ui.ctx().pixels_per_point();
                    let crect = out.rect;
                    let cpx = (
                        (crect.center().x * ppp).round() as i32,
                        (crect.center().y * ppp).round() as i32,
                    );
                    if cpx != self.last_composer_px {
                        log::info!("COMPOSER pxcx={} pxcy={} ppp={}", cpx.0, cpx.1, ppp);
                        self.last_composer_px = cpx;
                    }

                    let send = ui.add_sized([84.0, 42.0], egui::Button::new("Kirim"));
                    let srect = send.rect;
                    let spx = (
                        (srect.center().x * ppp).round() as i32,
                        (srect.center().y * ppp).round() as i32,
                    );
                    if !self.send_logged && self.frame > 1 {
                        log::info!("SEND pxcx={} pxcy={}", spx.0, spx.1);
                        self.send_logged = true;
                    }

                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (send.clicked() || enter) && !self.composer.trim().is_empty() {
                        let text = self.composer.trim().to_string();
                        log::info!(
                            "SENT_TO_AGENT chars={} text={:?}",
                            text.chars().count(),
                            text
                        );
                        let active = self.active;
                        self.tools.push(ToolEvent {
                            label: format!("mock:reply({} tok)", "?"),
                            ok: true,
                        });
                        self.agent.send(&mut self.sessions, active, &text, now);
                        // Send dikirim: composer kosong lewat jalur programatik.
                        self.ime.replace(&mut self.composer, "");
                    }

                    let chars = self.composer.chars().count();
                    if chars != self.last_composer_chars {
                        log::info!(
                            "COMPOSER_TEXT chars={} text={:?}",
                            chars,
                            self.composer
                        );
                        self.last_composer_chars = chars;
                    }
                });
            });

        if self.frame == 1 {
            let ppp = ui.ctx().pixels_per_point();
            let rect = ui.ctx().content_rect();
            log::info!(
                "UI_READY sessions={} active={} screen={}x{} ppp={}",
                self.sessions.len(),
                self.active,
                (rect.width() * ppp).round() as i32,
                (rect.height() * ppp).round() as i32,
                ppp
            );
        }
    }
}

impl eframe::App for ChatApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Inherent method, bukan rekursi ke trait.
        ChatApp::ui(self, ui);
    }
}

fn seed_sessions() -> Vec<Session> {
    vec![
        Session {
            id: "s1".into(),
            title: "Rekap Penjualan Oktober".into(),
            msgs: vec![
                Msg {
                    role: Role::User,
                    text: "rekap penjualan oktober dong".into(),
                    streaming: false,
                },
                Msg {
                    role: Role::Agent,
                    text: "Penjualan Oktober: Rp 812 juta, naik 6,4% dari September. Top: P2 38%, KHL 27%, PT 19%.".into(),
                    streaming: false,
                },
                Msg {
                    role: Role::Tool,
                    text: "pms:query_sales (ok, 3 tabel)".into(),
                    streaming: false,
                },
            ],
        },
        Session {
            id: "s2".into(),
            title: "Status joyboy".into(),
            msgs: vec![
                Msg {
                    role: Role::User,
                    text: "status server joyboy?".into(),
                    streaming: false,
                },
                Msg {
                    role: Role::Agent,
                    text: "Load 0.4, RAM 3.1/3.8 GB, disk 71%. Semua container hidup, nol OOM 24 jam.".into(),
                    streaming: false,
                },
            ],
        },
        Session {
            id: "s3".into(),
            title: "Sesi Baru".into(),
            msgs: vec![Msg {
                role: Role::Agent,
                text: "Sesi baru siap. Ketik apa aja, jawaban masih dari mock provider.".into(),
                streaming: false,
            }],
        },
    ]
}

fn seed_tools() -> Vec<ToolEvent> {
    vec![
        ToolEvent {
            label: "pms:query_sales".into(),
            ok: true,
        },
        ToolEvent {
            label: "bash:uptime".into(),
            ok: true,
        },
    ]
}
