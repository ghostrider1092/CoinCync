#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <bundle-dir> <destination-dir> [html-filename] [--replace-all]" >&2
  exit 2
fi

SOURCE_DIR="$(cd "$1" && pwd -P)"
DESTINATION="${2%/}"
HTML_NAME="${3:-index.html}"
MODE="${4:-preserve}"

if [ -z "$DESTINATION" ] || [ "$DESTINATION" = "/" ]; then
  echo "refusing unsafe explorer destination: ${DESTINATION:-<empty>}" >&2
  exit 1
fi
case "$HTML_NAME" in
  ""|*/*|*\\*)
    echo "explorer HTML filename must be a basename: $HTML_NAME" >&2
    exit 1
    ;;
esac
if [ "$MODE" != "preserve" ] && [ "$MODE" != "--replace-all" ]; then
  echo "unknown explorer installation mode: $MODE" >&2
  exit 2
fi

for required in "$HTML_NAME" explorer.css theme-init.js app.scripts.html; do
  if [ ! -s "$SOURCE_DIR/$required" ]; then
    echo "missing or empty explorer bundle asset: $required" >&2
    exit 1
  fi
done
if [ ! -d "$SOURCE_DIR/app" ]; then
  echo "missing explorer bundle application directory: $SOURCE_DIR/app" >&2
  exit 1
fi

declared_scripts=()
script_prefix='<script src="'
script_suffix='"></script>'
while IFS= read -r raw || [ -n "$raw" ]; do
  line="${raw%$'\r'}"
  if [ -z "$line" ]; then
    continue
  fi
  if [[ "$line" != "$script_prefix"*"$script_suffix" ]]; then
    echo "invalid explorer application manifest entry: $line" >&2
    exit 1
  fi
  relative="${line#"$script_prefix"}"
  relative="${relative%"$script_suffix"}"
  declared_scripts+=("$relative")
done < "$SOURCE_DIR/app.scripts.html"
if [ "${#declared_scripts[@]}" -eq 0 ]; then
  echo "explorer application manifest contains no scripts" >&2
  exit 1
fi

declare -A seen_scripts=()
for relative in "${declared_scripts[@]}"; do
  case "$relative" in
    app/*/*.js)
      echo "nested explorer application asset path is not supported: $relative" >&2
      exit 1
      ;;
    app/*.js) ;;
    *)
      echo "invalid explorer application asset path: $relative" >&2
      exit 1
      ;;
  esac
  if [ -n "${seen_scripts[$relative]+present}" ]; then
    echo "duplicate explorer application asset: $relative" >&2
    exit 1
  fi
  if [ ! -s "$SOURCE_DIR/$relative" ]; then
    echo "missing or empty explorer application asset: $relative" >&2
    exit 1
  fi
  seen_scripts["$relative"]=1
done

DEST_PARENT="$(dirname "$DESTINATION")"
DEST_NAME="$(basename "$DESTINATION")"
mkdir -p "$DEST_PARENT"
DESTINATION="$DEST_PARENT/$DEST_NAME"

if [ -L "$DESTINATION" ]; then
  echo "refusing to replace symlinked explorer destination: $DESTINATION" >&2
  exit 1
fi
if [ -e "$DESTINATION" ] && [ ! -d "$DESTINATION" ]; then
  echo "explorer destination is not a directory: $DESTINATION" >&2
  exit 1
fi

stage_dir="$(mktemp -d "$DEST_PARENT/.${DEST_NAME}.stage.XXXXXX")"
backup_dir=""

cleanup() {
  status=$?
  if [ -n "$stage_dir" ] && [ -d "$stage_dir" ]; then
    rm -rf -- "$stage_dir"
  fi
  if [ "$status" -ne 0 ] && [ -n "$backup_dir" ] &&
     [ -e "$backup_dir" ] && [ ! -e "$DESTINATION" ]; then
    if mv -- "$backup_dir" "$DESTINATION"; then
      backup_dir=""
    else
      echo "explorer rollback failed; previous tree retained at $backup_dir" >&2
    fi
  fi
  if [ "$status" -eq 0 ] && [ -n "$backup_dir" ] && [ -e "$backup_dir" ]; then
    rm -rf -- "$backup_dir"
  fi
  exit "$status"
}
trap cleanup EXIT

if [ "$MODE" = "--replace-all" ]; then
  cp -a "$SOURCE_DIR/." "$stage_dir/"
  rm -f -- "$stage_dir/app.scripts.html"
elif [ -d "$DESTINATION" ]; then
  cp -a "$DESTINATION/." "$stage_dir/"
fi

rm -rf -- "$stage_dir/app"
mkdir -p "$stage_dir/app"
for relative in "${declared_scripts[@]}"; do
  cp "$SOURCE_DIR/$relative" "$stage_dir/$relative"
done
chmod 0755 "$stage_dir/app"
chmod 0644 "$stage_dir/app/"*.js

if [ "$MODE" = "preserve" ]; then
  cp "$SOURCE_DIR/explorer.css" "$stage_dir/explorer.css"
  cp "$SOURCE_DIR/theme-init.js" "$stage_dir/theme-init.js"
  cp "$SOURCE_DIR/$HTML_NAME" "$stage_dir/$HTML_NAME"
  chmod 0644 "$stage_dir/$HTML_NAME" "$stage_dir/explorer.css" "$stage_dir/theme-init.js"
fi
chmod 0755 "$stage_dir"

backup_candidate="$DEST_PARENT/.${DEST_NAME}.previous.$$.${RANDOM}"
if [ -e "$backup_candidate" ]; then
  echo "explorer backup path already exists: $backup_candidate" >&2
  exit 1
fi
backup_dir="$backup_candidate"
if [ -e "$DESTINATION" ]; then
  mv -- "$DESTINATION" "$backup_dir"
fi
if ! mv -- "$stage_dir" "$DESTINATION"; then
  if [ -n "$backup_dir" ] && [ -e "$backup_dir" ]; then
    mv -- "$backup_dir" "$DESTINATION"
    backup_dir=""
  fi
  echo "failed to activate explorer bundle" >&2
  exit 1
fi
stage_dir=""

if [ -n "$backup_dir" ] && [ -e "$backup_dir" ]; then
  rm -rf -- "$backup_dir"
fi
backup_dir=""
trap - EXIT
