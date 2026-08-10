#!/bin/sh
# Reproducible release build — RFC 0 §9.
#
#   ./build-reproducible.sh            build, print the hash
#   ./build-reproducible.sh --verify   build twice from two paths and compare
#
# RFC 0 §9: "a user who cannot verify the binary matches the source is trusting
# the author personally, which is the trust relationship this design exists to
# avoid." Verification means two builds of one source producing the same bytes
# on different machines, in different directories.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
HOST=$(rustc -vV | sed -n 's/^host: //p')

# Linkers stamp a build identifier that is not derived from the content, so two
# builds of identical source differ in it — and on Mach-O the ad-hoc signature
# covers the UUID, so 16 bytes propagate into the signature too. Found by
# `--verify`: same size, 47 differing bytes, all in the load commands.
case "$(uname -s)" in
    Darwin) LINKARG='"-C","link-arg=-Wl,-no_uuid"' ;;
    Linux)  LINKARG='"-C","link-arg=-Wl,--build-id=none"' ;;
    *)      LINKARG='' ;;
esac

# Build one copy. $1 is the source root, $2 the target directory.
#
# Flags go in `target.<triple>.rustflags` rather than `RUSTFLAGS`, and
# `--target` is passed explicitly. Both matter:
#
#   * `RUSTFLAGS` takes precedence over the target config, so setting both
#     silently discards the config — the first attempt here did exactly that
#     and the linker flag never applied.
#   * Without an explicit `--target`, Cargo does not separate host build
#     scripts from target artifacts, so the flags reach build scripts too. A
#     build-script executable linked without a UUID will not load: dyld
#     refuses it with "missing LC_UUID load command", and the build dies in
#     `curve25519-dalek`.
build() {
    src=$1
    out=$2
    flags="\"--remap-path-prefix=$src=/krab\",\"--remap-path-prefix=$CARGO_HOME_DIR=/cargo\""
    [ -n "$LINKARG" ] && flags="$flags,$LINKARG"

    # `--locked` refuses to update Cargo.lock: without it a dependency
    # published since the lock was written is picked up silently, and the build
    # is reproducible only until someone else's release.
    #
    # Incremental compilation is off because it caches per-machine state that
    # changes codegen unit boundaries.
    ( cd "$src" && CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0 \
        cargo build --release --locked --target "$HOST" --target-dir "$out" \
            -p krab-tui --config "target.$HOST.rustflags=[$flags]" )
}

BIN="$HOST/release/krab"

if [ "${1:-}" = "--verify" ]; then
    # Two *different directories*, which is the test that matters: building
    # twice in one place would pass with no remapping at all.
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    cp -R "$ROOT" "$TMP/copy"
    rm -rf "$TMP/copy/target" "$TMP/copy/fuzz/target"

    build "$ROOT" "$ROOT/target/repro-a" >/dev/null 2>&1
    build "$TMP/copy" "$TMP/copy/target-b" >/dev/null 2>&1

    A=$(shasum -a 256 "$ROOT/target/repro-a/$BIN" | cut -d' ' -f1)
    B=$(shasum -a 256 "$TMP/copy/target-b/$BIN" | cut -d' ' -f1)
    echo "path A  $A"
    echo "path B  $B"
    if [ "$A" = "$B" ]; then
        echo "REPRODUCIBLE"
    else
        echo "NOT REPRODUCIBLE"
        cmp -l "$ROOT/target/repro-a/$BIN" "$TMP/copy/target-b/$BIN" | wc -l
        exit 1
    fi
else
    build "$ROOT" "$ROOT/target"
    shasum -a 256 "$ROOT/target/$BIN"
fi
