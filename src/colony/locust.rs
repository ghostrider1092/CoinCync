//! locust — density-adaptive mode (solitary ↔ gregarious).
//!
//! Locusts live quietly alone until crowding tips them into a gregarious
//! swarm phase — a genuine behavioural switch driven by density. This caste
//! gives a node the same two-phase behaviour for **relay aggressiveness**:
//! calm and conservative when the network is quiet ("solitary"), and
//! aggressive swarm-relay when load or attack density spikes ("gregarious").
//! It lets the node spend bandwidth where it matters — cheap when idle,
//! all-in under a censorship/partition push — without a human flipping a
//! switch.
//!
//! ## Hysteresis, so the mode doesn't flap (rule D.4)
//!
//! Density hovering around a single threshold would make a naive switch
//! oscillate every tick, which is itself a fingerprint *and* wastes
//! resources. So the two transitions use **different** thresholds: a
//! solitary node only goes gregarious at [`HIGH_DENSITY_PCT`], and only
//! falls back to solitary once density drops all the way to
//! [`LOW_DENSITY_PCT`]. The band between is "sticky" — you keep whatever
//! mode you were in.
//!
//! ## Advisory only
//!
//! The mode is a *recommendation* about how hard to relay **public**
//! blocks/announcements; it never touches transaction privacy (Dandelion++
//! stem behaviour is not the locust's to change) and changes no consensus
//! rule. Pure state machine, deterministic.

/// Relay-aggressiveness phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwarmMode {
    /// Quiet network: conservative relay, minimal fan-out.
    Solitary,
    /// Neutral band before either extreme is reached (start state).
    Transitional,
    /// Congestion/attack: aggressive swarm-relay, wide fan-out.
    Gregarious,
}

/// Density at/above which a solitary node switches to gregarious (percent).
pub const HIGH_DENSITY_PCT: u8 = 70;
/// Density at/below which a gregarious node relaxes back to solitary
/// (percent). Strictly below [`HIGH_DENSITY_PCT`] — the gap *is* the
/// hysteresis.
pub const LOW_DENSITY_PCT: u8 = 30;

/// Density-adaptive mode with hysteresis. Feed it a density reading each
/// tick via [`update`](Locust::update); it returns the (possibly
/// unchanged) mode.
#[derive(Clone, Copy, Debug)]
pub struct Locust {
    mode: SwarmMode,
}

impl Default for Locust {
    fn default() -> Self {
        Self { mode: SwarmMode::Transitional }
    }
}

impl Locust {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current mode without advancing state.
    pub fn mode(&self) -> SwarmMode {
        self.mode
    }

    /// Update from a density reading (`0..=100`) and an attack flag, and
    /// return the resulting mode.
    ///
    /// `under_attack` forces [`SwarmMode::Gregarious`] regardless of
    /// density — an active attack is the one signal we don't want to sit
    /// in a sticky band for. Otherwise the transition is hysteretic:
    /// - from [`Solitary`](SwarmMode::Solitary): rise to gregarious only at
    ///   [`HIGH_DENSITY_PCT`].
    /// - from [`Gregarious`](SwarmMode::Gregarious): fall to solitary only
    ///   at [`LOW_DENSITY_PCT`].
    /// - the in-between band holds the current mode.
    pub fn update(&mut self, density_pct: u8, under_attack: bool) -> SwarmMode {
        self.mode = if under_attack {
            SwarmMode::Gregarious
        } else {
            match self.mode {
                SwarmMode::Solitary => {
                    if density_pct >= HIGH_DENSITY_PCT {
                        SwarmMode::Gregarious
                    } else {
                        SwarmMode::Solitary
                    }
                }
                SwarmMode::Gregarious => {
                    if density_pct <= LOW_DENSITY_PCT {
                        SwarmMode::Solitary
                    } else {
                        SwarmMode::Gregarious
                    }
                }
                SwarmMode::Transitional => {
                    if density_pct >= HIGH_DENSITY_PCT {
                        SwarmMode::Gregarious
                    } else if density_pct <= LOW_DENSITY_PCT {
                        SwarmMode::Solitary
                    } else {
                        SwarmMode::Transitional
                    }
                }
            }
        };
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_transitional_and_resolves_on_first_extreme() {
        let mut l = Locust::new();
        assert_eq!(l.mode(), SwarmMode::Transitional);
        // Mid band from the start: stays transitional.
        assert_eq!(l.update(50, false), SwarmMode::Transitional);
        // Cross high: gregarious.
        assert_eq!(l.update(HIGH_DENSITY_PCT, false), SwarmMode::Gregarious);
    }

    #[test]
    fn quiet_network_settles_solitary() {
        let mut l = Locust::new();
        assert_eq!(l.update(LOW_DENSITY_PCT, false), SwarmMode::Solitary);
        assert_eq!(l.update(0, false), SwarmMode::Solitary);
    }

    #[test]
    fn hysteresis_prevents_flapping_in_the_band() {
        let mut l = Locust::new();
        // Go gregarious.
        l.update(90, false);
        assert_eq!(l.mode(), SwarmMode::Gregarious);
        // Density falls into the middle band — must STAY gregarious, not
        // flap back at the high threshold.
        assert_eq!(l.update(50, false), SwarmMode::Gregarious);
        assert_eq!(l.update(HIGH_DENSITY_PCT - 1, false), SwarmMode::Gregarious);
        // Only a full drop to the low threshold relaxes it.
        assert_eq!(l.update(LOW_DENSITY_PCT, false), SwarmMode::Solitary);
        // And now the middle band holds solitary, not flipping at low+1.
        assert_eq!(l.update(50, false), SwarmMode::Solitary);
    }

    #[test]
    fn attack_forces_gregarious_regardless_of_density() {
        let mut l = Locust::new();
        l.update(0, false);
        assert_eq!(l.mode(), SwarmMode::Solitary);
        assert_eq!(l.update(0, true), SwarmMode::Gregarious, "attack overrides low density");
    }

    #[test]
    fn thresholds_are_inclusive() {
        let mut l = Locust::new();
        // exactly HIGH from transitional -> gregarious.
        assert_eq!(l.update(HIGH_DENSITY_PCT, false), SwarmMode::Gregarious);
        let mut m = Locust::new();
        // exactly LOW from transitional -> solitary.
        assert_eq!(m.update(LOW_DENSITY_PCT, false), SwarmMode::Solitary);
    }
}
