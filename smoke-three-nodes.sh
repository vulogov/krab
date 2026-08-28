#!/bin/sh
# A—B—C: three nodes, two peerings, and the hop in the middle.
#
#     ./smoke-three-nodes.sh            run the tests
#     ./smoke-three-nodes.sh --manual   set up three homes and print the steps
#
# ---------------------------------------------------------------------------
# What this is for
# ---------------------------------------------------------------------------
#
# `smoke.sh` proves two peered nodes can talk. It does not prove the thing the
# protocol exists for: that A and C, who have never met and share no key, can
# exchange mail because B carries it. B is not a router — it holds ciphertext
# it cannot open and offers it onward at the next reconciliation, and that is
# the whole of the mechanism.
#
# Everything here runs through the same command parser the pane uses, for the
# reason `smoke.sh` gives: driving a full-screen terminal application from a
# shell script tests the terminal emulation and not the program.

set -eu

HOME_A="${KRAB_SMOKE_HOME:-/tmp/krab-three}/a"
HOME_B="${KRAB_SMOKE_HOME:-/tmp/krab-three}/b"
HOME_C="${KRAB_SMOKE_HOME:-/tmp/krab-three}/c"
BIN="./target/release/krab"

if [ "${1:-}" = "--manual" ]; then
    [ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }
    mkdir -p "$HOME_A" "$HOME_B" "$HOME_C" "${KRAB_SMOKE_HOME:-/tmp/krab-three}/exchange"
    EX="${KRAB_SMOKE_HOME:-/tmp/krab-three}/exchange"
    cat <<MANUAL

Three nodes in a line. A and C never peer with each other.

  terminal 1:  $BIN --home $HOME_A --listen 127.0.0.1:41000
  terminal 2:  $BIN --home $HOME_B --listen 127.0.0.1:41001
  terminal 3:  $BIN --home $HOME_C --listen 127.0.0.1:41002

Always pass --home. Without it the store is the current directory, so the
same command in two shells is two different nodes — which looks exactly like
data loss and is not.

In each, once: \`init\`, then \`status\`.

Peer A with B, and B with C, by the ceremony in \`./smoke.sh --manual\`. Do it
twice; B runs it once facing A and once facing C. A and C do not peer.

B must carry public content for the channel half to work, and so must A and C
if they are to host each other's posts:

  channel carry on          arms and prints what you are agreeing to
  channel carry on          commits it

Then on each node:

  channel new
  channel post              composer; Ctrl-D, then Enter to publish

Connect the line and move everything:

  on A:  connect <B> tcp 127.0.0.1:41001   then  force-send <B>
  on C:  connect <B> tcp 127.0.0.1:41002   then  force-send <B>
  on B:  force-send <A>  and  force-send <C>

Two things to look for, and they are the point:

  * A message A sent to C arrives, and B never displays it. B holds the
    object and cannot open it — that is a relay, not a router.
  * Each node's Channels tab lists all three channels, including the two it
    cannot post to.

Then quit all three with Ctrl-Q and start them again. The peerings, their
agreed terms, the channels and the posts must all still be there. A channel
that vanishes on restart was the epoch-key bug fixed in d91cea5; if you see
it again, that is a regression and not a surprise.

MANUAL
    exit 0
fi

echo "Krab smoke — three nodes, A—B—C, and the hop in the middle."
echo
echo "Driving the flow through the same command parser the pane uses."
echo "For the real interface, run: ./smoke-three-nodes.sh --manual"
echo

# Named individually rather than run as a filter, so that a test being
# renamed or removed fails this script loudly instead of silently narrowing
# what it covers.
for t in \
    a_message_reaches_a_node_two_hops_away \
    channel_posts_from_three_nodes_reach_them_all \
    a_peering_and_its_terms_survive_a_restart \
    an_epoch_key_minted_after_init_is_persisted \
    an_epoch_yields_the_same_key_across_a_restart \
    a_channel_post_crosses_to_a_follower_and_is_read \
    received_mail_reaches_the_disk_not_only_the_pane
do
    printf '  %-56s ' "$t"
    if cargo test --quiet -p krab-tui -- --exact "tests::$t" >/dev/null 2>&1; then
        echo "ok"
    else
        echo "FAILED"
        cargo test -p krab-tui -- --exact "tests::$t" 2>&1 | tail -20
        exit 1
    fi
done

echo
echo "A's message reaches a node two hops away, carried by a middle node that"
echo "cannot read it and does not drop it. Channel posts written on three"
echo "nodes reach all three. A peering, its agreed terms, and the epoch key"
echo "everything long-lived is sealed under all survive a restart."
echo
echo "What this does not cover: the ratatui frame, a real network, three"
echo "operators, and reconciliation's scheduling — the carry here is direct."
echo "Run --manual for the parts a test cannot reach."
