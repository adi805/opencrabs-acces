// Mock provider: streaming canned reply token-per-token ke transcript sesi.
// UI render state transcript saja, tanpa salinan optimistis (semangat
// AC-016/017: yang tampil = state yang tersimpan).
use crate::app::{Msg, Role, Session};
use std::collections::VecDeque;

pub struct MockAgent {
    queue: VecDeque<String>,
    next_tick_at: f64,
    total_tokens: usize,
    streaming: bool,
}

impl MockAgent {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            next_tick_at: 0.0,
            total_tokens: 0,
            streaming: false,
        }
    }

    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// Push pesan user + placeholder agent, isi antrian token jawaban.
    pub fn send(&mut self, sessions: &mut [Session], active: usize, text: &str, now: f64) {
        let s = &mut sessions[active];
        s.msgs.push(Msg {
            role: Role::User,
            text: text.to_string(),
            streaming: false,
        });
        s.msgs.push(Msg {
            role: Role::Agent,
            text: String::new(),
            streaming: true,
        });
        let body = canned_reply(text);
        self.queue = body.split_inclusive(' ').map(str::to_string).collect();
        self.total_tokens = self.queue.len();
        self.streaming = true;
        self.next_tick_at = now + 0.08;
        log::info!("MOCK_STREAM_START tokens={}", self.total_tokens);
    }

    /// Reveal token per tick. Returns Some(total_tokens) saat reply tamat.
    pub fn tick(&mut self, sessions: &mut [Session], active: usize, now: f64) -> Option<usize> {
        if !self.streaming || now < self.next_tick_at {
            return None;
        }
        if let Some(tok) = self.queue.pop_front() {
            if let Some(m) = sessions[active].msgs.last_mut() {
                m.text.push_str(&tok);
            }
            self.next_tick_at = now + 0.08;
            if self.queue.is_empty() {
                self.streaming = false;
                if let Some(m) = sessions[active].msgs.last_mut() {
                    m.streaming = false;
                }
                return Some(self.total_tokens);
            }
        }
        None
    }
}

fn canned_reply(text: &str) -> String {
    let lower = text.to_lowercase();
    if lower.contains("rekap") || lower.contains("penjualan") {
        "Siap. Rekap penjualan Oktober: bersih Rp 812 juta, naik 6,4% dari September. Top kontributor: P2 38%, KHL 27%, PT 19%. Catatan: piutang P3 masih nunggu cicilan ke-2. Mau dipecah per gudang atau per minggu?".to_string()
    } else if lower.contains("server") || lower.contains("joyboy") || lower.contains("status") {
        "Status joyboy: load 0.4, RAM 3.1/3.8 GB, disk 71%. Semua container hidup (caddy, listmonk, umami, filebrowser, AdGuardHome). Tidak ada OOM dalam 24 jam terakhir.".to_string()
    } else {
        "Siap, gue catat. Ini masih mock provider, jawabannya canned. Pas core opencrabs kebundel (task 3), jawaban datang beneran dari agent core lewat loopback.".to_string()
    }
}
