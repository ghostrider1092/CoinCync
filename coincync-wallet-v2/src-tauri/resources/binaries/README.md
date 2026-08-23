# Bundled binaries (populated at release time)

This directory is the bundle target for `tauri.conf.json` →
`bundle.resources = ["resources/binaries/*"]`. The release/packaging step drops
the platform binaries here so the desktop app ships self-contained (no separate
downloads):

- `coincync-node`
- `coincync-wallet`
- `coincync-rig`
- `coincync-swap` (v1.1+, behind its own audit)

It is intentionally empty in a source checkout except for this note. Tauri v2's
`tauri-build` validates the `resources` glob at build time and fails if it
matches **nothing**, so this file also keeps `cargo build`/`tauri build` green
in a fresh clone. The release pipeline overwrites/augments this directory with
the real, signed binaries for each target triple.
