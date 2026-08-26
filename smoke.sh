#!/bin/sh
# Two nodes, from nothing to a delivered message.
#
#     ./smoke.sh            walk the whole flow, printing each step
#     ./smoke.sh --manual   print the commands to type, and set up two homes
#
# ---------------------------------------------------------------------------
# Why this is not two `krab` processes in a subshell
# ---------------------------------------------------------------------------
#
# `krab` is a full-screen terminal application. Its commands are typed into a
# pane, not read from stdin, so a shell script cannot drive it without a
# pseudo-terminal and a fragile pile of `expect`. What such a script would
# actually test is the terminal emulation.
#
# So the automatic mode runs the end-to-end tests, which drive two `App`s
# through **the same command parser the pane uses** — `type_command(&mut a,
# "peer offer")` is the operator typing `peer offer`. That is the real flow
# minus the ratatui frame, and it is what the release is tested on.
#
# `--manual` is for when the frame is the point: it creates two homes and
# prints the commands, and you run the two nodes yourself.

set -eu

BIN="./target/release/krab"
HOME_A="${KRAB_SMOKE_HOME:-/tmp/krab-smoke}/alice"
HOME_B="${KRAB_SMOKE_HOME:-/tmp/krab-smoke}/bob"

if [ "${1:-}" = "--manual" ]; then
    [ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }
    mkdir -p "$HOME_A" "$HOME_B" "$(dirname "$HOME_A")/exchange"
    EX="$(dirname "$HOME_A")/exchange"
    cat <<MANUAL

Two nodes, two homes, two terminals.

  terminal 1:  $BIN --home $HOME_A --listen 127.0.0.1:40000
  terminal 2:  $BIN --home $HOME_B --listen 127.0.0.1:40001

In each, once:

  init                            identity, and the backup shown exactly once
  status                          says what is still missing

Peer them. Both ends run the same steps — there is no initiator:

  peer offer                      writes peer.card into that home
  peer pad $EX/<yours>.pad

Copy both files across; on one host $EX is your courier. Then in each:

  peer accept $EX/<theirs>.card
  peer verified <their-short-id>  you compared the fingerprint words
  peer seal $EX/<theirs>.pad in-person
  peer countersign <file>         both signatures on the credential

Then:

  connect <their-short-id> tcp 127.0.0.1:4000{0,1}
  message <their-short-id>        type, Ctrl-D to seal and queue
  force-send <their-short-id>     do not wait for the Poisson draw

Two things this shortcut costs, and they are real:

  * \`peer verified\` on one host asserts you compared fingerprint words aloud.
    You did not. That comparison is the only thing standing between a peering
    and a machine-in-the-middle (RFC 3 §11 step 2); everything else in the
    ceremony is bookkeeping around it. Fine for a functional test, and not a
    peering to trust.

  * \`force-send\` reconciles on your keystroke. RFC 5 §6.1 keeps sync
    intervals uncorrelated with message events precisely so an observer cannot
    tell when you composed something. The verb says so each time it runs.

The short id is the first four bytes of the node id in hex — eight characters,
shown on the frame of the messages pane and the output pane.

MANUAL
    exit 0
fi

echo "Krab smoke — two nodes, from nothing to a delivered message."
echo
echo "Driving the flow through the same command parser the pane uses."
echo "For the real interface, run: ./smoke.sh --manual"
echo

# The tests named here each walk a whole path end to end. Named individually
# rather than run as a filter so that a test being renamed or removed fails
# this script loudly, instead of silently narrowing what it covers.
for t in \
    a_message_reaches_a_peer_by_stick_using_only_typed_commands \
    a_message_crosses_between_two_nodes_by_reconciliation \
    a_peered_node_can_send_and_the_object_is_readable_by_the_recipient \
    a_message_encapsulated_to_a_prekey_is_readable \
    a_group_message_is_sealed_once_per_member_and_opens \
    courier_only_peering_completes_with_no_network \
    init_ends_by_saying_whether_the_node_is_ready
do
    printf '  %-62s ' "$t"
    if cargo test --quiet -p krab-tui -- --exact "tests::$t" >/dev/null 2>&1; then
        echo "ok"
    else
        echo "FAILED"
        cargo test -p krab-tui -- --exact "tests::$t" 2>&1 | tail -20
        exit 1
    fi
done

echo
echo "A message goes from one node to another: over a stick, over a live"
echo "reconciliation, to a prekey, and to a group — with all interfaces down"
echo "for the courier case, which is RFC 3 §11.3's release gate."
echo
echo "What this does not cover: the ratatui frame, a real network, and a"
echo "second operator. Every test above was written by whoever wrote the code."
