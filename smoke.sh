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

Peer them. Both ends run the same steps — there is no initiator. The order
below is the order the app itself prints, and it is not interchangeable:

  peer offer                      writes peer.card into that home

Copy each home's peer.card across as <name>.card; on one host $EX is your
courier. Then in each:

  peer accept $EX/<theirs>.card   prints both fingerprints to compare aloud
  peer pad $EX/<yours>.pad        your SECRET half — carry it, don't leave it
  peer seal $EX/<theirs>.pad in-person

\`peer seal\` is what records the terms, and only then does the link exist to
say anything about. So verification comes after it, not before:

  peer verified <their-short-id>  you compared the fingerprint words

\`peer seal\` wrote <their-short-id>.credential into your home, carrying only
your signature. Swap those two files and countersign what you receive:

  peer countersign $EX/<theirs>.credential

Then, and \`connect\` must come first — force-send uses an existing session
and will not dial one for you:

  connect <their-short-id> tcp 127.0.0.1:4000{0,1}
  send <their-short-id>           type, Ctrl-D to seal and queue
  force-send <their-short-id>     do not wait for the Poisson draw

\`send\` addresses the composition to that peer. \`message\` also opens a
composer, but an unaddressed one — it will not reach anybody.

To send a picture instead of typing a body:

  send <their-short-id> --picture <file.png>

It is decoded and re-encoded before it leaves — no EXIF, no GPS, no ICC, and
no setting to keep them (RFC 8 §6). The bytes that arrive are pixel data this
program generated, so the received file is NOT identical to the one you sent.
That is the point. At the other end the row is marked \`▣\`, and:

  picture save <file.png>   write it out
  picture show              draw it in the message pane

\`picture show\` needs a terminal advertising 24-bit colour (COLORTERM), and
Krab will not open a viewer for you at any point.

---------------------------------------------------------------------------
Channels — public, signed, permanent
---------------------------------------------------------------------------

A channel is the unencrypted half: anyone holding a post can read it, and it
cannot be edited or withdrawn. Two steps in this flow ask twice on purpose,
and both are the same kind of decision.

On both nodes, if you want them to host public content at all:

  channel carry on          arms, and prints what you are agreeing to
  channel carry on          again — this one commits it

Off is the default (RFC 6 §3.6): what a node hosts has consequences that
depend on where the operator lives. With it off, a link carries sealed mail
only and channel posts will not cross — which looks exactly like a delivery
failure if you have forgotten this.

On the publishing node:

  channel new               one posting identity per node
  channel list              shows its short id — give that to readers
  channel post the meeting is moved
  channel post the meeting is moved

The first \`channel post\` of a session does not publish. It prints
PUBLIC — SIGNED — PERMANENT and waits; the second one publishes and says
"published post 1". A single invocation looks like it worked and did not.

Then move it, as before:

  connect <their-short-id> tcp 127.0.0.1:4000{0,1}
  force-send <their-short-id>

On the reading node, once a post has arrived:

  channel follow <channel-short-id>
  channel list

Follow only works after one of that channel's posts is in your corpus —
there is no directory to look one up in, which is why the id has to reach you
some other way. Ctrl-T switches to the Channels tab to read them.

A channel post carries text and nothing else: \`--picture\` has no meaning
here and would be published as those characters. Pictures are private-message
only in this build.

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
    init_ends_by_saying_whether_the_node_is_ready \
    a_channel_post_crosses_to_a_follower_and_is_read \
    a_channel_post_has_no_attachment_path \
    a_peering_made_while_running_is_visible_without_a_restart \
    received_mail_reaches_the_disk_not_only_the_pane \
    forcing_over_a_live_session_reports_that_it_started
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
echo "for the courier case, which is RFC 3 §11.3's release gate. A channel"
echo "post crosses to a follower and is read, and carries no attachment."
echo
echo "The last three are regressions, and each one was found by running two"
echo "real nodes rather than by reading the code: a peering made while"
echo "running could not read its own mail, received mail never reached the"
echo "disk, and a forced send that worked reported that it had not."
echo
echo "What this does not cover: the ratatui frame, a real network, and a"
echo "second operator. Every test above was written by whoever wrote the code."
