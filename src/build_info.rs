/// Build metadata stamped at compile time from `build.rs`.
///
/// These values are surfaced via RPC so operators can verify what code is
/// currently running on each node without shell access.
pub fn git_commit() -> &'static str {
    option_env!("COINCYNC_BUILD_GIT_SHA").unwrap_or("unknown")
}

pub fn git_dirty() -> bool {
    option_env!("COINCYNC_BUILD_GIT_DIRTY").unwrap_or("0") == "1"
}

pub fn build_profile() -> &'static str {
    option_env!("COINCYNC_BUILD_PROFILE").unwrap_or("unknown")
}
