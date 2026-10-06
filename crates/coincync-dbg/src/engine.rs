//! The "debuggee": a deterministic replay of CoinCync difficulty retargeting.
//!
//! This is the ENGINE half of the DAP vertical slice. It drives the REAL
//! consensus function [`calculate_difficulty`] over a sequence of blocks, one
//! step at a time, exposing after each step the decoded state a developer wants
//! to see (height, inter-block gap, target, resulting difficulty, floor status).
//!
//! Stepping a block is the domain analogue of stepping a source line, and the
//! "difficulty at/under the floor" condition is the domain analogue of an
//! exception breakpoint — the exact #191 failure made observable by stepping.
//! Everything here is pure and deterministic, so `stepBack`/reverse debugging is
//! a future increment (re-run from the start to position N).

use coincync::consensus::difficulty::{
    calculate_difficulty, calculate_difficulty_from_target, DifficultyBlock, MIN_DIFFICULTY,
};
use coincync::primitives::Hash;

/// Target block time the steady prefix is built on (seconds). Matches
/// `TARGET_BLOCK_TIME`; kept local so the engine needs no extra constant export.
const TARGET_BLOCK_TIME: u64 = 120;

/// Decoded state at one replayed block — what the IDE shows in the Variables
/// pane and the stack frame.
#[derive(Debug, Clone)]
pub struct StepState {
    /// 0-based index among the PROGRAM blocks (maps to a source line).
    pub index: usize,
    pub height: u64,
    pub timestamp: u64,
    /// Seconds since the previous block (the gap that drives ASERT).
    pub gap_secs: u64,
    /// Work-factor difficulty of the target this block was retargeted to.
    pub difficulty: u128,
    /// The retarget target, upper-16-bytes hex (how the chain stores it).
    pub target_hex: String,
    /// True when difficulty has reached the consensus floor region — the
    /// semantic breakpoint condition (the #191 collapse symptom).
    pub at_floor: bool,
}

/// A deterministic difficulty-replay session.
pub struct ReplayEngine {
    /// Full chain so far (steady prefix + executed program blocks). ASERT reads
    /// a window of this, so the prefix must exist before the first program block.
    history: Vec<DifficultyBlock>,
    /// Per-program-block inter-block gaps (seconds). `program[i]` is the time
    /// from the previous block to program block `i`.
    program: Vec<u64>,
    /// Next program index to execute.
    pos: usize,
    /// Difficulty at or below this fires the floor breakpoint. Defaults to the
    /// consensus floor; a launch arg can raise it to catch a sharp drop earlier.
    pub floor_threshold: u128,
    /// The most recently executed step (for stackTrace/variables between steps).
    pub last: Option<StepState>,
    /// Human description of the loaded scenario (shown on launch).
    pub scenario_name: String,
}

impl ReplayEngine {
    /// Encode a u128 target into the upper 16 bytes of a 32-byte hash — the same
    /// layout the difficulty module uses, so `calculate_difficulty_from_target`
    /// round-trips it. (`u128_to_target` is private to the consensus crate.)
    fn target_for_difficulty(d: u128) -> Hash {
        let t = (u128::MAX / d.max(1)).max(1);
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&t.to_be_bytes());
        Hash::from_bytes(bytes)
    }

    /// Build a steady equilibrium chain of `n` blocks at `start_difficulty`,
    /// exactly `TARGET_BLOCK_TIME` apart, so ASERT is at rest before the program.
    fn steady_prefix(n: u64, start_difficulty: u128) -> Vec<DifficultyBlock> {
        let target = Self::target_for_difficulty(start_difficulty);
        (0..n)
            .map(|h| DifficultyBlock {
                height: h,
                timestamp: h * TARGET_BLOCK_TIME,
                target,
            })
            .collect()
    }

    /// The built-in demo: a chain at difficulty ~2^18 that then receives a run of
    /// very slow blocks (far over target), so ASERT eases difficulty down to the
    /// MIN_DIFFICULTY floor — the collapse an idle/slow network produces, and the
    /// condition #191 made catastrophic. Stepping it fires the floor breakpoint.
    pub fn demo_floor_scenario() -> Self {
        const START_DIFF: u128 = 1 << 18; // 262,144
        let history = Self::steady_prefix(160, START_DIFF);
        // 20 blocks each ~1 day apart (86_400s >> 120s target) → sustained slow →
        // difficulty eases 2x/block (per the clamp) toward the floor.
        let program = vec![86_400u64; 20];
        ReplayEngine {
            history,
            program,
            pos: 0,
            floor_threshold: MIN_DIFFICULTY.saturating_mul(2),
            last: None,
            scenario_name: "demo: sustained-slow difficulty collapse (#191 class)".to_string(),
        }
    }

    /// Build from an explicit list of inter-block gaps (seconds), starting from a
    /// steady chain at `start_difficulty`. Lets a launch config replay any shape.
    pub fn from_gaps(name: impl Into<String>, start_difficulty: u128, gaps: Vec<u64>) -> Self {
        ReplayEngine {
            history: Self::steady_prefix(160, start_difficulty.max(MIN_DIFFICULTY)),
            program: gaps,
            pos: 0,
            floor_threshold: MIN_DIFFICULTY.saturating_mul(2),
            last: None,
            scenario_name: name.into(),
        }
    }

    /// Total number of program blocks (= source lines the IDE shows).
    pub fn program_len(&self) -> usize {
        self.program.len()
    }

    /// Whether every program block has been executed.
    pub fn is_finished(&self) -> bool {
        self.pos >= self.program.len()
    }

    /// Execute the next program block through the real retarget function and
    /// return its decoded state. `None` once the program is exhausted.
    pub fn step(&mut self) -> Option<StepState> {
        if self.is_finished() {
            return None;
        }
        let gap = self.program[self.pos];
        let tip = self.history.last().expect("prefix is non-empty");
        let height = tip.height + 1;
        let timestamp = tip.timestamp + gap;

        // The REAL consensus retarget — this is what makes the debugger show
        // true chain behaviour rather than a reimplementation.
        let target = calculate_difficulty(&self.history, height);
        let difficulty = calculate_difficulty_from_target(&target);

        self.history.push(DifficultyBlock {
            height,
            timestamp,
            target,
        });

        let state = StepState {
            index: self.pos,
            height,
            timestamp,
            gap_secs: gap,
            difficulty,
            target_hex: hex16(&target),
            at_floor: difficulty <= self.floor_threshold,
        };
        self.pos += 1;
        self.last = Some(state.clone());
        Some(state)
    }

    /// Run steps until the floor breakpoint fires or the program ends. Returns
    /// the breakpoint state if one fired, else `None` (ran to completion).
    pub fn run_to_breakpoint(&mut self) -> Option<StepState> {
        while let Some(state) = self.step() {
            if state.at_floor {
                return Some(state);
            }
        }
        None
    }

    /// One source "line" per program block — a readable disassembly the IDE
    /// shows while stepping (the stack frame points at the current line).
    pub fn source_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("# {}", self.scenario_name)];
        for (i, gap) in self.program.iter().enumerate() {
            lines.push(format!("block[{i:>3}]  gap={gap}s   retarget()"));
        }
        lines
    }
}

/// Upper-16-bytes hex of a target (the 128-bit precision the module works at).
fn hex16(h: &Hash) -> String {
    let b = h.as_bytes();
    let mut s = String::with_capacity(34);
    s.push_str("0x");
    for byte in &b[..16] {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_scenario_collapses_to_floor_and_stops() {
        let mut eng = ReplayEngine::demo_floor_scenario();
        let bp = eng.run_to_breakpoint().expect("sustained-slow must reach the floor");
        assert!(bp.at_floor, "breakpoint state must be at the floor");
        assert!(
            bp.difficulty <= MIN_DIFFICULTY * 2,
            "difficulty at the floor breakpoint: {}",
            bp.difficulty
        );
        // It should take only a handful of 2x-clamped eases to fall from 2^18.
        assert!(bp.index < 15, "floor reached unexpectedly late at step {}", bp.index);
    }

    #[test]
    fn steady_prefix_is_at_equilibrium() {
        // A short run of ON-TARGET blocks must NOT drift to the floor.
        let mut eng = ReplayEngine::from_gaps("steady", 1 << 18, vec![TARGET_BLOCK_TIME; 10]);
        let bp = eng.run_to_breakpoint();
        assert!(bp.is_none(), "on-target blocks must not collapse difficulty");
        assert_eq!(eng.last.unwrap().index, 9, "all steps executed");
    }

    #[test]
    fn source_lines_cover_every_program_block() {
        let eng = ReplayEngine::demo_floor_scenario();
        // one header line + one per program block
        assert_eq!(eng.source_lines().len(), eng.program_len() + 1);
    }
}
