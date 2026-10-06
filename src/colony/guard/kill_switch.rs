//! Global colony Act kill switch.
//!
//! Default **DISARMED**. While disarmed, [`super::ColonyGuards::authorize`]
//! denies every action, so a freshly-started node — including on mainnet —
//! can never take a colony Act. Arming is an explicit, reversible operator
//! decision (config opt-in at startup, or the authenticated `colony_arm`
//! control path at runtime).

use std::sync::atomic::{AtomicBool, Ordering};

/// One-bit, thread-safe, default-off gate. `false` = disarmed = Act blocked.
#[derive(Debug)]
pub struct KillSwitch(AtomicBool);

impl KillSwitch {
    /// A disarmed switch — the only constructor, so you cannot accidentally
    /// create an armed one.
    pub const fn new_disarmed() -> Self {
        Self(AtomicBool::new(false))
    }

    /// True only after an explicit [`arm`](Self::arm).
    pub fn is_armed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Allow Act. Only ever called on explicit operator opt-in.
    pub fn arm(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Block all Act again. Instant and reversible — the emergency stop.
    pub fn disarm(&self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new_disarmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disarmed() {
        assert!(!KillSwitch::new_disarmed().is_armed());
        assert!(!KillSwitch::default().is_armed());
    }

    #[test]
    fn arm_then_disarm() {
        let k = KillSwitch::new_disarmed();
        k.arm();
        assert!(k.is_armed());
        k.disarm();
        assert!(!k.is_armed());
    }
}
