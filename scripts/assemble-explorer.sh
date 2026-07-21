#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <src/explorer> <destination-index.html>" >&2
  exit 2
fi

SOURCE_ROOT="$(cd "$1" && pwd)"
MANIFEST="$SOURCE_ROOT/index.parts"
DESTINATION="$2"
if [ ! -f "$MANIFEST" ]; then
  echo "explorer source manifest missing: $MANIFEST" >&2
  exit 1
fi

mkdir -p "$(dirname "$DESTINATION")"
DESTINATION="$(cd "$(dirname "$DESTINATION")" && pwd)/$(basename "$DESTINATION")"
if [ "$DESTINATION" = "$SOURCE_ROOT" ] || [[ "$DESTINATION" == "$SOURCE_ROOT/"* ]]; then
  echo "refusing to write assembled output inside explorer sources" >&2
  exit 1
fi

temporary="$DESTINATION.tmp.$$"
trap 'rm -f "$temporary"' EXIT
: > "$temporary"

declare -A seen=()
part_count=0
while IFS= read -r part || [ -n "$part" ]; do
  case "$part" in
    ""|\#*) continue ;;
    /*|*\\*) echo "unsafe explorer source path: $part" >&2; exit 1 ;;
  esac
  case "/$part/" in
    *"/../"*) echo "unsafe explorer source path: $part" >&2; exit 1 ;;
  esac
  if [ -n "${seen[$part]+present}" ]; then
    echo "duplicate explorer source path: $part" >&2
    exit 1
  fi
  source_path="$SOURCE_ROOT/$part"
  if [ ! -s "$source_path" ]; then
    echo "missing or empty explorer source part: $part" >&2
    exit 1
  fi
  seen["$part"]=1
  cat "$source_path" >> "$temporary"
  part_count=$((part_count + 1))
done < "$MANIFEST"

if [ "$part_count" -eq 0 ]; then
  echo "explorer source manifest contains no parts: $MANIFEST" >&2
  exit 1
fi
mv "$temporary" "$DESTINATION"
trap - EXIT
