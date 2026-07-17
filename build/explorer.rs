use std::collections::HashSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};

const SOURCE_ROOT: &str = "src/explorer";
const DOCUMENT_MANIFEST: &str = "src/explorer/index.parts";
const APP_MANIFEST: &str = "src/explorer/app.scripts.html";
const DOCUMENT_OUTPUT: &str = "explorer-index.html";
const APP_ASSETS_OUTPUT: &str = "explorer-app-assets.rs";

pub fn assemble() {
    println!("cargo:rerun-if-changed={DOCUMENT_MANIFEST}");
    let source_root = fs::canonicalize(SOURCE_ROOT)
        .unwrap_or_else(|e| panic!("cannot resolve explorer source root {SOURCE_ROOT}: {e}"));
    let document = assemble_document(&source_root);
    let app_assets = generate_app_assets(&source_root);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR"));

    fs::write(out_dir.join(DOCUMENT_OUTPUT), document)
        .unwrap_or_else(|e| panic!("cannot write assembled explorer HTML: {e}"));
    fs::write(out_dir.join(APP_ASSETS_OUTPUT), app_assets)
        .unwrap_or_else(|e| panic!("cannot write generated explorer application assets: {e}"));
}

fn assemble_document(source_root: &Path) -> Vec<u8> {
    let manifest = fs::read_to_string(DOCUMENT_MANIFEST).unwrap_or_else(|e| {
        panic!("cannot read explorer source manifest {DOCUMENT_MANIFEST}: {e}")
    });
    let mut assembled = Vec::new();
    let mut seen = HashSet::new();
    let mut part_count = 0;

    for entry in source_entries(&manifest) {
        let path = validated_source_path(source_root, entry, DOCUMENT_MANIFEST);
        if !seen.insert(path.clone()) {
            panic!("duplicate explorer source path in {DOCUMENT_MANIFEST}: {entry}");
        }
        println!("cargo:rerun-if-changed={SOURCE_ROOT}/{entry}");
        let bytes = fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read explorer source part {}: {e}", path.display()));
        if bytes.is_empty() {
            panic!("explorer source part is empty: {}", path.display());
        }
        assembled.extend_from_slice(&bytes);
        part_count += 1;
    }

    if part_count == 0 {
        panic!("{DOCUMENT_MANIFEST} contains no explorer source parts");
    }
    assembled
}

fn generate_app_assets(source_root: &Path) -> String {
    let manifest = fs::read_to_string(APP_MANIFEST).unwrap_or_else(|e| {
        panic!("cannot read explorer application manifest {APP_MANIFEST}: {e}")
    });
    let mut generated = String::from(
        "/// Ordered classic-script assets generated from src/explorer/app.scripts.html.\n\
         pub const EXPLORER_APP_ASSETS: &[(&str, &str)] = &[\n",
    );
    let mut seen = HashSet::new();
    let mut script_count = 0;

    for (line_index, raw) in manifest.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let script = line
            .strip_prefix("<script src=\"")
            .and_then(|value| value.strip_suffix("\"></script>"))
            .unwrap_or_else(|| {
                panic!(
                    "invalid application manifest entry at {APP_MANIFEST}:{}: {line}",
                    line_index + 1
                )
            });
        let script_path = Path::new(script);
        if script_path.parent() != Some(Path::new("app"))
            || script_path.extension().and_then(|value| value.to_str()) != Some("js")
        {
            panic!("application manifest entry must be an app/*.js path: {script}");
        }

        let path = validated_source_path(source_root, script, APP_MANIFEST);
        if !seen.insert(path) {
            panic!("duplicate explorer application asset in {APP_MANIFEST}: {script}");
        }
        println!("cargo:rerun-if-changed={SOURCE_ROOT}/{script}");
        let include_path = format!("{SOURCE_ROOT}/{script}");
        writeln!(
            generated,
            "    ({script:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/\", {include_path:?}))),"
        )
        .expect("writing generated Rust source cannot fail");
        script_count += 1;
    }

    if script_count == 0 {
        panic!("{APP_MANIFEST} contains no application scripts");
    }
    reject_undeclared_app_scripts(source_root, &seen);
    generated.push_str("];\n");
    generated
}

fn reject_undeclared_app_scripts(source_root: &Path, declared: &HashSet<PathBuf>) {
    let app_dir = source_root.join("app");
    let entries = fs::read_dir(&app_dir)
        .unwrap_or_else(|e| panic!("cannot read explorer application directory: {e}"));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot read explorer application directory entry: {e}"))
            .path();
        if path.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("js")
            && !declared.contains(&path)
        {
            panic!(
                "explorer application script is not declared in {APP_MANIFEST}: {}",
                path.display()
            );
        }
    }
}

fn source_entries(manifest: &str) -> impl Iterator<Item = &str> {
    manifest
        .lines()
        .map(str::trim)
        .filter(|entry| !entry.is_empty() && !entry.starts_with('#'))
}

fn validated_source_path(source_root: &Path, entry: &str, manifest: &str) -> PathBuf {
    let relative = Path::new(entry);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        panic!("unsafe explorer source path in {manifest}: {entry}");
    }

    let source_path = Path::new(SOURCE_ROOT).join(relative);
    let path = fs::canonicalize(&source_path).unwrap_or_else(|e| {
        panic!(
            "cannot resolve explorer source path {}: {e}",
            source_path.display()
        )
    });
    if !path.starts_with(source_root) {
        panic!("explorer source escapes source root in {manifest}: {entry}");
    }
    if !path.is_file() {
        panic!("explorer source is not a file in {manifest}: {entry}");
    }
    path
}
