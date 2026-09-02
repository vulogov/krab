//! Launching and driving `tor` — RFC 4 §5.2's service half.
//!
//! Krab starts its own `tor`, on arguments alone, and talks to it over an
//! ephemeral control port. Nothing here reads or writes a configuration file
//! that an operator is expected to maintain.
//!
//! # No configuration, and what that costs
//!
//! `Documentation/NO-CONFIG.md`: config files "may be lost, spoofed, faked,
//! leaked", so every operation is driven from the command pane, a chord, or
//! the CLI. `tor`, left alone, does the opposite — it reads `/etc/tor/torrc`
//! and `/etc/tor/torrc-defaults` at startup, so a node's anonymity properties
//! would be set by a file Krab never sees and an attacker with root might
//! have edited.
//!
//! There is no tor option meaning "read nothing". `-f` and `--defaults-torrc`
//! can only be pointed *somewhere*. So [`TorLaunch`] writes a
//! **zero-byte** file in Krab's own run directory and points both at it,
//! truncating it at every start and verifying it is empty afterwards. It is
//! not configuration — it is the absence of configuration, spelled in the only
//! way tor accepts.
//!
//! The verification is not ceremony. If something else wrote to that path
//! between starts, the difference between "empty" and "not empty" is the
//! difference between the operator's Tor settings and somebody else's, and it
//! is silent in every other respect.
//!
//! # Why the daemon is a child and not a service
//!
//! `--__OwningControllerProcess <pid>` makes tor exit when Krab exits, so a
//! crashed or killed node does not leave an onion service published and
//! answering for an identity nothing is holding. Combined with [`Drop`] and
//! [`TorProcess::stop`], there are three independent paths that stop the
//! daemon, which is the right number for something the panic wipe must be able
//! to kill immediately.
//!
//! # What is not here
//!
//! Bootstrap takes tens of seconds and descriptor publication longer (§5.2),
//! so nothing in this module blocks for the whole of it. [`TorProcess::launch`]
//! returns as soon as the control port answers, and
//! [`TorProcess::bootstrap`] is polled by the caller — which is what lets the
//! interface satisfy §5.2's "clients MUST show bootstrap progress or users
//! will believe the node is broken at every start".

use crate::backend::socks;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long to wait for tor to write its control port file.
///
/// Tor writes it once the control listener is up, which is early — before any
/// network work. Ten seconds is generous for a process that has not yet
/// touched the network, and short enough that a wrong binary or a refused
/// port is reported while the operator is still looking at the screen.
pub const CONTROL_READY_S: u64 = 10;

/// How long any single control-port exchange may take.
///
/// `GETINFO` and `ADD_ONION` are local and answer immediately; the exception
/// is `ADD_ONION`, which builds introduction circuits and can legitimately
/// take tens of seconds on a fresh bootstrap.
pub const CONTROL_TIMEOUT_S: u64 = 120;

/// The file name of the deliberately empty torrc.
const EMPTY_TORRC: &str = "torrc.empty";
/// Where tor is told to write the control port it chose.
const CONTROL_PORT_FILE: &str = "control-port";
/// Where tor is told to write the control authentication cookie.
const COOKIE_FILE: &str = "control-cookie";
/// Tor's own state directory. Tor owns this; Krab only chooses where it is.
const DATA_DIR: &str = "data";

/// What went wrong.
#[derive(Debug)]
#[non_exhaustive]
pub enum TorError {
    /// The tor binary could not be found, or is not usable.
    Binary(String),
    /// A path Krab was given is not one it will accept.
    Path(String),
    /// Tor started and then exited, or never became ready.
    Launch(String),
    /// The control port refused a command, with tor's own reply.
    Control(String),
    /// Underlying I/O failure.
    Io(std::io::Error),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Binary(s) => write!(f, "tor binary: {s}"),
            TorError::Path(s) => write!(f, "path: {s}"),
            TorError::Launch(s) => write!(f, "tor did not start: {s}"),
            TorError::Control(s) => write!(f, "tor control port: {s}"),
            TorError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for TorError {
    fn from(e: std::io::Error) -> TorError {
        TorError::Io(e)
    }
}

/// Where tor is, and where it may write.
#[derive(Debug, Clone)]
pub struct TorLaunch {
    binary: Option<PathBuf>,
    run_dir: PathBuf,
}

impl TorLaunch {
    /// Use whatever `tor` is on `PATH`.
    ///
    /// The convenient default and the weaker one: `PATH` is inherited from
    /// whatever started Krab, and a writable directory early in it is a
    /// classic substitution. [`TorLaunch::at`] is the answer for an operator
    /// who cares, and [`TorProcess::binary`] reports which was used either way
    /// so the choice is visible rather than assumed.
    pub fn on_path(run_dir: impl Into<PathBuf>) -> TorLaunch {
        TorLaunch {
            binary: None,
            run_dir: run_dir.into(),
        }
    }

    /// Use the tor binary at an explicit **absolute** path.
    ///
    /// # Why relative paths are refused rather than resolved
    ///
    /// A relative path is interpreted against the current working directory,
    /// which Krab does not control and an attacker may. Resolving it here
    /// would turn `tor` into "whatever is in the directory the node happened
    /// to be started from" — precisely the substitution the operator chose
    /// this constructor to avoid. Refusing is the only answer that keeps the
    /// guarantee the argument was for.
    pub fn at(
        binary: impl Into<PathBuf>,
        run_dir: impl Into<PathBuf>,
    ) -> Result<TorLaunch, TorError> {
        let binary = binary.into();
        if !binary.is_absolute() {
            // **The reason differs by platform, and so does the message.**
            //
            // On Windows a path like `\tor` or `/tor` has a root and no drive
            // letter, so it is *drive-relative*: it resolves against whichever
            // drive the process is on. `Path::is_absolute` is false for it,
            // which is correct and is exactly the ambiguity this argument
            // exists to refuse — but telling an operator that `\tor` is
            // "relative" reads as a bug to them, because it does not look
            // relative and on unix it would not be.
            //
            // Found by the first Windows CI run, which failed a test asserting
            // `/nonexistent/tor` was absent-not-relative. It is absent on
            // unix and relative on Windows, and the check was more right than
            // the test.
            let why = if cfg!(windows) {
                "must name a drive — a path beginning with a slash or backslash \
                 resolves against whichever drive this process happens to be \
                 on, which is not something you or krab control"
            } else {
                "must be absolute, or it resolves against a working directory \
                 neither you nor krab controls"
            };
            return Err(TorError::Path(format!(
                "{} will not do: an explicit tor path {why}",
                binary.display()
            )));
        }
        if !binary.is_file() {
            return Err(TorError::Binary(format!(
                "{} is not a file",
                binary.display()
            )));
        }
        Ok(TorLaunch {
            binary: Some(binary),
            run_dir: run_dir.into(),
        })
    }

    /// The empty torrc, the data directory, and a clean slate for the two
    /// files tor will write.
    ///
    /// Called at every start. Truncating rather than creating-if-absent is the
    /// point: a stale control-port file from a previous run would be read as
    /// this run's port and Krab would authenticate to a daemon it did not
    /// start.
    fn provision(&self) -> Result<(), TorError> {
        std::fs::create_dir_all(self.run_dir.join(DATA_DIR))?;

        // The zero-byte torrc, rewritten every start.
        let torrc = self.run_dir.join(EMPTY_TORRC);
        std::fs::write(&torrc, b"")?;

        // **Verified, not assumed.** If anything else wrote here, the gap
        // between empty and not-empty is the gap between the operator's Tor
        // settings and somebody else's, and nothing else would show it.
        let len = std::fs::metadata(&torrc)?.len();
        if len != 0 {
            return Err(TorError::Path(format!(
                "{} is {len} bytes after being truncated — something else is \
                 writing there, and krab will not start tor against a config \
                 file it did not write",
                torrc.display()
            )));
        }

        // Stale artefacts from a previous run. `control-port` in particular
        // would otherwise be read as this run's.
        for f in [CONTROL_PORT_FILE, COOKIE_FILE] {
            let p = self.run_dir.join(f);
            if p.exists() {
                shred(&p)?;
            }
        }
        Ok(())
    }

    /// The argument vector. Separated out so it can be asserted on.
    fn args(&self) -> Vec<String> {
        let p = |f: &str| self.run_dir.join(f).display().to_string();
        vec![
            // Both config sources, pointed at the same empty file. `-f` alone
            // would leave `/etc/tor/torrc-defaults` in play.
            "-f".into(),
            p(EMPTY_TORRC),
            "--defaults-torrc".into(),
            p(EMPTY_TORRC),
            // Tor's own state. It caches the consensus here; that is tor's
            // business and not Krab configuration.
            "--DataDirectory".into(),
            p(DATA_DIR),
            // Ephemeral, both of them: the kernel picks, tor reports.
            "--SocksPort".into(),
            "auto".into(),
            "--ControlPort".into(),
            "auto".into(),
            "--ControlPortWriteToFile".into(),
            p(CONTROL_PORT_FILE),
            // Cookie rather than HashedControlPassword, which is an S2K
            // construction over **SHA-1** — a primitive this workspace does
            // not have and would not add for one authentication step. The
            // cookie is tor's own file, read once and shredded at stop.
            "--CookieAuthentication".into(),
            "1".into(),
            "--CookieAuthFile".into(),
            p(COOKIE_FILE),
            // Tor exits when this process does. See the module note.
            "--__OwningControllerProcess".into(),
            std::process::id().to_string(),
            // RFC 3 §12 forbids retaining per-object provenance; tor's logs
            // are not Krab's, but a node that scrubs its own addresses and
            // leaves tor logging peer addresses at INFO has not achieved
            // anything. `SafeLogging 1` is tor's default and is set
            // explicitly because the empty torrc means nothing else will.
            "--SafeLogging".into(),
            "1".into(),
            // Nothing reads tor's stdout; the control port is the interface.
            "--Log".into(),
            "warn stdout".into(),
        ]
    }
}

/// A running tor, authenticated to.
pub struct TorProcess {
    child: Child,
    control: TcpStream,
    socks_port: u16,
    binary: String,
    run_dir: PathBuf,
}

impl TorProcess {
    /// Start tor and authenticate to its control port.
    ///
    /// Returns as soon as the control port answers — **not** when tor has
    /// bootstrapped, which takes tens of seconds and is what
    /// [`TorProcess::bootstrap`] is for.
    pub fn launch(cfg: &TorLaunch) -> Result<TorProcess, TorError> {
        cfg.provision()?;

        let binary = cfg.binary.clone().unwrap_or_else(|| PathBuf::from("tor"));
        let shown = binary.display().to_string();

        let mut child = Command::new(&binary)
            .args(cfg.args())
            // Nothing reads these. Piping without reading would let tor block
            // on a full pipe; inheriting would scribble over the TUI.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| {
                TorError::Binary(format!(
                    "{shown}: {e}. Install tor, or give an absolute path with \
                     `start-tor <path>`"
                ))
            })?;

        // Wait for the control port file, watching for the child dying.
        let port_file = cfg.run_dir.join(CONTROL_PORT_FILE);
        let control_port = match wait_for_control_port(&port_file, &mut child) {
            Ok(p) => p,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };

        let mut me = TorProcess {
            child,
            control: TcpStream::connect(("127.0.0.1", control_port))?,
            socks_port: 0,
            binary: shown,
            run_dir: cfg.run_dir.clone(),
        };
        me.control
            .set_read_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_S)))?;
        me.control
            .set_write_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_S)))?;

        if let Err(e) = me.authenticate(&cfg.run_dir.join(COOKIE_FILE)) {
            me.stop();
            return Err(e);
        }
        me.socks_port = match me.query_socks_port() {
            Ok(p) => p,
            Err(e) => {
                me.stop();
                return Err(e);
            }
        };
        Ok(me)
    }

    /// The SOCKS port tor chose, for [`socks::connect_through`].
    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    /// Which binary was actually started.
    ///
    /// Reported so that "whatever is on PATH" is a visible answer rather than
    /// an assumed one.
    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// Bootstrap progress — RFC 4 §5.2's "clients MUST show bootstrap
    /// progress".
    ///
    /// Cheap enough to call on the interface's tick.
    pub fn bootstrap(&mut self) -> Result<Bootstrap, TorError> {
        let reply = self.command("GETINFO status/bootstrap-phase")?;
        Ok(Bootstrap::parse(&reply))
    }

    /// Publish an onion service, returning its `.onion` address.
    ///
    /// `key` is Krab's derived permanent key (RFC 4 §5.2), so the address is
    /// the same at every start. `auth` is the restricted-discovery client set:
    /// base32 x25519 public keys from peer credentials. **An empty `auth` set
    /// publishes an unrestricted service**, which §5.2 permits only for the
    /// contact endpoint — the sync endpoint must never be published without
    /// one, and the caller is what enforces that.
    pub fn add_onion(
        &mut self,
        key_base64: &str,
        virtual_port: u16,
        target_port: u16,
        auth: &[String],
    ) -> Result<String, TorError> {
        // `DiscardPK`: the key was supplied, so tor must not hand it back —
        // it would otherwise appear in the reply and therefore in any buffer
        // that reply passes through.
        let mut flags = String::from("DiscardPK");
        if !auth.is_empty() {
            flags.push_str(",V3Auth");
        }
        let mut cmd = format!(
            "ADD_ONION ED25519-V3:{key_base64} Flags={flags} \
             Port={virtual_port},127.0.0.1:{target_port}"
        );
        for client in auth {
            cmd.push_str(" ClientAuthV3=");
            cmd.push_str(client);
        }

        let reply = self.command(&cmd);
        // The command carried the private key. Overwrite the buffer before it
        // is dropped — RFC 7 §9's "fixed buffers", applied to the one string
        // in this module that holds key material.
        overwrite(&mut cmd);

        let reply = reply?;
        for line in reply.lines() {
            if let Some(id) = line
                .trim_start_matches(|c: char| c.is_ascii_digit() || c == '-' || c == '+')
                .strip_prefix("ServiceID=")
            {
                return Ok(format!("{}.onion", id.trim()));
            }
        }
        Err(TorError::Control(format!(
            "ADD_ONION returned no ServiceID: {reply}"
        )))
    }

    /// Withdraw a published service — `DEL_ONION`.
    ///
    /// The descriptor stops being republished and the service becomes
    /// unreachable within one descriptor lifetime. This is what makes RFC 3
    /// §9.2's contact endpoint "freely rotatable" in the operational sense
    /// rather than only the cryptographic one: a contact address that could be
    /// derived afresh but never withdrawn would accumulate, and every one of
    /// them would still be answering.
    ///
    /// Idempotent from the caller's side: a service tor has already forgotten
    /// gives `552`, which is reported and is not a condition worth handling
    /// differently from success.
    pub fn del_onion(&mut self, address: &str) -> Result<(), TorError> {
        let id = address.trim_end_matches(".onion");
        self.command(&format!("DEL_ONION {id}")).map(|_| ())
    }

    /// Stop tor now.
    ///
    /// **Kill, not a polite shutdown.** This is what the panic wipe calls, and
    /// a wipe that waited for a daemon to close its circuits would be a wipe
    /// that waited. Tor has no state Krab needs preserved: the onion key is
    /// derived and never stored, and the consensus cache is public data.
    ///
    /// Idempotent, and safe to call on a process that has already exited.
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The cookie authenticated a control port that no longer exists, but
        // it is 32 bytes of secret that tor wrote to disk and Krab chose the
        // location of — so Krab removes it the way it removes everything else
        // (`Documentation/SECURE-DELETE.md`).
        let _ = shred(&self.run_dir.join(COOKIE_FILE));
        let _ = shred(&self.run_dir.join(CONTROL_PORT_FILE));
    }

    /// Whether the daemon is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    // ---- control protocol ----

    fn authenticate(&mut self, cookie_path: &Path) -> Result<(), TorError> {
        let mut cookie = std::fs::read(cookie_path).map_err(|e| {
            TorError::Control(format!(
                "cannot read the control cookie at {}: {e}",
                cookie_path.display()
            ))
        })?;
        // The hex is bound and erased too. `format!("… {}", hex(&cookie))`
        // copies it into `cmd` and drops the temporary with the cookie still
        // in it — `cmd` was overwritten below and the intermediate was not,
        // which left 64 bytes of the control-port credential on the heap for
        // every start.
        let mut encoded = hex(&cookie);
        let mut cmd = format!("AUTHENTICATE {encoded}");
        overwrite(&mut encoded);
        cookie.iter_mut().for_each(|b| *b = 0);

        let r = self.command(&cmd);
        overwrite(&mut cmd);
        r.map(|_| ())
    }

    fn query_socks_port(&mut self) -> Result<u16, TorError> {
        let reply = self.command("GETINFO net/listeners/socks")?;
        // 250-net/listeners/socks="127.0.0.1:9050"
        let port = reply
            .split('"')
            .nth(1)
            .and_then(|a| a.rsplit(':').next())
            .and_then(|p| p.trim().parse::<u16>().ok())
            .ok_or_else(|| {
                TorError::Control(format!("could not read a SOCKS port from: {reply}"))
            })?;
        Ok(port)
    }

    /// One command, one reply. Returns the reply body; errors on any status
    /// that is not 2xx.
    fn command(&mut self, cmd: &str) -> Result<String, TorError> {
        self.control.write_all(cmd.as_bytes())?;
        self.control.write_all(b"\r\n")?;
        self.control.flush()?;
        read_reply(&mut self.control)
    }
}

impl Drop for TorProcess {
    /// The third of the three paths that stop the daemon.
    fn drop(&mut self) {
        self.stop();
    }
}

/// Read one control-port reply.
///
/// The protocol marks the last line by putting a **space** after the status
/// code, where continuation lines use `-` or `+`. Reading until "a line
/// starting with 250" would stop at the first of a multi-line reply and leave
/// the rest to be misread as the answer to the next command.
fn read_reply(stream: &mut TcpStream) -> Result<String, TorError> {
    read_reply_from(&mut BufReader::new(stream))
}

/// The parsing half, over any reader, so it can be tested without a socket.
fn read_reply_from(reader: &mut impl BufRead) -> Result<String, TorError> {
    let mut body = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(TorError::Control("the control port closed".into()));
        }
        body.push_str(&line);
        let b = line.as_bytes();
        if b.len() >= 4 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2].is_ascii_digit() {
            if b[3] == b' ' {
                // Final line. 2xx is success; anything else is tor refusing,
                // and tor's own text is more useful than any paraphrase.
                if b[0] != b'2' {
                    return Err(TorError::Control(body.trim().to_string()));
                }
                return Ok(body);
            }
        } else {
            return Err(TorError::Control(format!("unparseable reply: {body}")));
        }
    }
}

/// Poll for the control port file, giving up if tor dies or the wait expires.
fn wait_for_control_port(path: &Path, child: &mut Child) -> Result<u16, TorError> {
    let deadline = Instant::now() + Duration::from_secs(CONTROL_READY_S);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(TorError::Launch(format!(
                "tor exited with {status} before opening a control port. The \
                 usual causes are a port it could not bind and a data \
                 directory it could not write."
            )));
        }
        if let Ok(text) = std::fs::read_to_string(path) {
            // `PORT=127.0.0.1:41235`
            if let Some(port) = text
                .trim()
                .rsplit(':')
                .next()
                .and_then(|p| p.trim().parse::<u16>().ok())
            {
                return Ok(port);
            }
        }
        if Instant::now() >= deadline {
            return Err(TorError::Launch(format!(
                "no control port after {CONTROL_READY_S}s"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Bootstrap progress, for the interface to show — RFC 4 §5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    /// 0–100.
    pub percent: u8,
    /// Tor's own one-line summary.
    pub summary: String,
}

impl Bootstrap {
    /// Whether tor is ready to carry traffic.
    pub fn is_done(&self) -> bool {
        self.percent >= 100
    }

    /// Parse `GETINFO status/bootstrap-phase`'s reply.
    ///
    /// Tolerant on purpose: an unparseable reply becomes 0% with tor's text
    /// rather than an error. This is polled on the interface tick, and a
    /// progress indicator that returns `Err` because tor phrased something
    /// unexpectedly would take the node down for a cosmetic reason.
    fn parse(reply: &str) -> Bootstrap {
        let percent = reply
            .split("PROGRESS=")
            .nth(1)
            .and_then(|r| {
                r.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|d| d.parse::<u8>().ok())
            })
            .unwrap_or(0);
        let summary = reply
            .split("SUMMARY=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap_or("starting")
            .to_string();
        Bootstrap { percent, summary }
    }
}

/// Overwrite a `String`'s bytes in place before it is dropped.
///
/// Reaches the allocation the string currently holds, which is where the
/// control command carrying the onion key lives. It does not reach a block an
/// earlier growth abandoned — `Documentation/SECURE-DELETE.md` records that as
/// a bound on the mechanism rather than a defect in it.
fn overwrite(s: &mut String) {
    // SAFETY-free: `clear` keeps the allocation, and writing zeros through the
    // `String`'s own bytes requires no unsafe when done via `replace_range`.
    let n = s.len();
    s.replace_range(.., &"\0".repeat(n));
    s.clear();
}

/// Overwrite a file with random-ish bytes, then remove it.
///
/// The project's secure-delete discipline, applied to the two files tor writes
/// into a directory Krab chose. Deliberately not perfect — see
/// `Documentation/SECURE-DELETE.md` on what overwriting can and cannot promise
/// on a journalling or copy-on-write filesystem.
fn shred(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len() as usize;
        if len > 0 {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                // A fixed non-zero pattern. This is not cryptographic and does
                // not need to be: the goal is that the previous contents are
                // not what is on the platter, not that the new contents are
                // unpredictable.
                let junk = vec![0xA5u8; len];
                let _ = f.write_all(&junk);
                let _ = f.sync_all();
            }
        }
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Lower-case hex, for `AUTHENTICATE`.
fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

/// Dial `host:port` through this tor's SOCKS port.
///
/// The join between the two halves of §5.2: [`TorProcess`] runs the daemon,
/// [`socks`] speaks to it, and the returned stream is an ordinary
/// [`TcpStream`] ready for the Noise handshake every other backend uses.
pub fn dial(socks_port: u16, host: &str, port: u16) -> Result<TcpStream, crate::Error> {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))?;
    // A circuit through three relays plus a rendezvous is slow, and §5.2 says
    // so: "a ~3 s circuit RTT is irrelevant to store-and-forward". The
    // deadline is generous for that reason and is still a deadline.
    s.set_read_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_S)))?;
    s.set_write_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_S)))?;
    socks::connect_through(&mut s, host, port)?;
    Ok(s)
}

/// A link to one peer's onion service — RFC 4 §5.2's client half.
///
/// This is the piece that was missing: [`dial`] existed and returned a
/// [`TcpStream`], and nothing in the workspace implemented [`crate::Fabric`] over it,
/// so `connect <peer> tor <addr>` fell through to the TCP branch. That is
/// worse than an error. `TcpStream::connect("…onion:9001")` hands the name to
/// the system resolver, which does not know `.onion` — so the dial fails
/// *after* the operator's DNS server, and anyone watching it, has been told
/// which hidden service this node was looking for. The whole point of §5.2 is
/// that nobody learns that.
///
/// # Outbound only, and that is the architecture rather than a limitation
///
/// [`accept`](crate::Fabric::accept) always yields `None`. Inbound traffic to an
/// onion service does not arrive here: tor terminates the rendezvous circuit
/// itself and forwards the stream to the local port named in `ADD_ONION`'s
/// `Port=` argument, where the ordinary listener is already waiting. There is
/// nothing for this type to accept, and a variant that pretended otherwise
/// would be a second listener racing the first for the same connections.
///
/// So a node reachable over Tor is running two things: `start-tor`, which
/// publishes the service and points it at the listen port, and the listener
/// that port belongs to. `TorFabric` is only how this node *dials out*.
///
/// # The static-key check is unchanged, and that is the point
///
/// An onion address authenticates the *service*, not the peer behind it, and
/// those are different claims: the address proves whoever answers holds the
/// onion key, which is a key this node's own peer may have had stolen. So the
/// Noise IK handshake runs exactly as it does over TCP, against the static key
/// from the credential (RFC 4 §4.1), and a mismatch is the same hard failure.
/// Tor supplies location privacy; it supplies no identity Krab is willing to
/// use.
pub struct TorFabric {
    profile: crate::profile::LinkProfile,
    /// The local SOCKS port of the tor this node launched.
    socks_port: u16,
    /// The peer's `.onion` address, without a port.
    host: String,
    /// The virtual port on that service.
    port: u16,
    local_static: [u8; 32],
    /// The peer's expected static public key, **from their credential**.
    expected_peer: [u8; 32],
}

/// The virtual port Krab publishes on, and dials by default.
///
/// A hidden service's port space is its own — it is not a port on any host, so
/// there is no conflict to avoid and no registry to consult. A constant is
/// therefore better than a setting: both ends must agree, and nothing an
/// operator could usefully vary is expressed by varying it.
pub const ONION_PORT: u16 = 9001;

impl TorFabric {
    /// A link toward `host` through the tor listening on `socks_port`.
    ///
    /// `host` is an address, not an address and port: the port is
    /// [`ONION_PORT`]. Accepting `host:port` here would let a caller pass a
    /// string that parses two ways depending on whether the address contains a
    /// colon, and `.onion` addresses do not.
    pub fn new(
        profile: crate::profile::LinkProfile,
        socks_port: u16,
        host: impl Into<String>,
        local_static: [u8; 32],
        expected_peer: [u8; 32],
    ) -> TorFabric {
        TorFabric {
            profile,
            socks_port,
            host: host.into(),
            port: ONION_PORT,
            local_static,
            expected_peer,
        }
    }

    /// Override the virtual port. For a peer publishing on something else.
    pub fn with_port(mut self, port: u16) -> TorFabric {
        self.port = port;
        self
    }

    /// The address this fabric dials.
    pub fn host(&self) -> &str {
        &self.host
    }
}

impl crate::Fabric for TorFabric {
    fn profile(&self) -> &crate::profile::LinkProfile {
        &self.profile
    }

    fn connect(&self) -> Result<Box<dyn crate::Session>, crate::Error> {
        // Deadlines are already armed inside `dial` for the SOCKS negotiation,
        // which is the step that can hang: tor accepts the local connection
        // immediately and then says nothing for as long as circuit building
        // takes. They are re-armed below for the handshake and again for the
        // session, because the three have different right answers and this
        // runs on the interface thread — the same argument `TcpFabric::connect`
        // makes at length.
        let mut stream = dial(self.socks_port, &self.host, self.port)?;
        crate::backend::listener::arm_handshake(&stream)?;
        let noise = crate::noise::handshake_initiator(
            &mut stream,
            &self.local_static,
            &self.expected_peer,
        )?;
        crate::backend::listener::arm_session_for(&stream, self.profile.session_timeout())?;
        Ok(Box::new(crate::noise::StreamSession::new(stream, noise)))
    }

    /// Always `None` — see the type's note. Inbound arrives at the listener
    /// the onion service forwards to, not here.
    fn accept(&self) -> Result<Option<Box<dyn crate::Session>>, crate::Error> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("krab-tor-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// **The empty torrc is written, is empty, and both config flags point at
    /// it.** This is the whole no-configuration guarantee; if `-f` were passed
    /// without `--defaults-torrc`, tor would still read
    /// `/etc/tor/torrc-defaults`.
    #[test]
    fn provisioning_writes_a_zero_byte_torrc_and_points_both_flags_at_it() {
        let dir = tmp("provision");
        let cfg = TorLaunch::on_path(&dir);
        cfg.provision().unwrap();

        let torrc = dir.join(EMPTY_TORRC);
        assert!(torrc.exists());
        assert_eq!(std::fs::metadata(&torrc).unwrap().len(), 0);

        let args = cfg.args();
        let path = torrc.display().to_string();
        let f = args.iter().position(|a| a == "-f").expect("-f missing");
        assert_eq!(args[f + 1], path);
        let d = args
            .iter()
            .position(|a| a == "--defaults-torrc")
            .expect("--defaults-torrc missing — /etc/tor/torrc-defaults would still be read");
        assert_eq!(args[d + 1], path);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Truncated at every start.** A leftover file from a previous run would
    /// otherwise be this run's configuration.
    #[test]
    fn provisioning_truncates_an_existing_torrc() {
        let dir = tmp("truncate");
        let cfg = TorLaunch::on_path(&dir);
        cfg.provision().unwrap();
        std::fs::write(dir.join(EMPTY_TORRC), b"SocksPort 9050\nExitRelay 1\n").unwrap();
        assert!(std::fs::metadata(dir.join(EMPTY_TORRC)).unwrap().len() > 0);

        cfg.provision().unwrap();
        assert_eq!(
            std::fs::metadata(dir.join(EMPTY_TORRC)).unwrap().len(),
            0,
            "a previous run's settings survived into this one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A stale control-port file is removed**, or Krab would authenticate to
    /// a daemon it did not start.
    #[test]
    fn provisioning_clears_stale_control_files() {
        let dir = tmp("stale");
        let cfg = TorLaunch::on_path(&dir);
        cfg.provision().unwrap();
        std::fs::write(dir.join(CONTROL_PORT_FILE), b"PORT=127.0.0.1:9999").unwrap();
        std::fs::write(dir.join(COOKIE_FILE), [7u8; 32]).unwrap();

        cfg.provision().unwrap();
        assert!(!dir.join(CONTROL_PORT_FILE).exists());
        assert!(!dir.join(COOKIE_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative tor path is refused — it would resolve against a working
    /// directory nobody controls, which is the attack the argument exists to
    /// prevent.
    ///
    /// # `/nonexistent/tor` is not absolute on Windows, and that is the point
    ///
    /// This test asserted that path gave `Binary` — absolute but absent — and
    /// it does on unix. **On Windows it gives `Path`**, because a leading
    /// slash with no drive letter is *drive-relative*: it resolves against
    /// whatever drive the process happens to be on, so
    /// `Path::is_absolute` is false for it and `at` refuses it as relative.
    ///
    /// That is the check being *more* right than this test assumed, not less.
    /// The argument exists so an operator's explicit tor path cannot be
    /// resolved against something they do not control, and on Windows the
    /// current drive is exactly such a thing. The first Windows CI run found
    /// it; nothing on a developer's Mac could have.
    ///
    /// So the fixture is per-platform and the drive-relative case is asserted
    /// on its own, rather than the assertion being loosened to accept either
    /// error — which would have hidden the difference instead of naming it.
    #[test]
    fn a_relative_binary_path_is_refused() {
        let dir = tmp("relative");
        assert!(matches!(TorLaunch::at("tor", &dir), Err(TorError::Path(_))));
        assert!(matches!(
            TorLaunch::at("./tor", &dir),
            Err(TorError::Path(_))
        ));

        // Absolute but absent is a different complaint, and says so.
        let absent = if cfg!(windows) {
            r"C:\nonexistent\tor"
        } else {
            "/nonexistent/tor"
        };
        assert!(
            matches!(TorLaunch::at(absent, &dir), Err(TorError::Binary(_))),
            "{absent} should be absent-not-relative on this platform"
        );

        // **Drive-relative, which exists only on Windows.** `\tor` and
        // `/tor` name a path on the *current* drive, so they are exactly the
        // ambiguity this argument refuses — and they are ordinary-looking
        // absolute paths to anyone reading a unix shell history.
        #[cfg(windows)]
        {
            assert!(matches!(
                TorLaunch::at(r"\nonexistent\tor", &dir),
                Err(TorError::Path(_))
            ));
            assert!(matches!(
                TorLaunch::at("/nonexistent/tor", &dir),
                Err(TorError::Path(_))
            ));
        }
    }

    /// The daemon is tied to this process's lifetime, and the argument
    /// carries *this* pid rather than a placeholder.
    #[test]
    fn the_daemon_is_owned_by_this_process() {
        let cfg = TorLaunch::on_path(tmp("owned"));
        let args = cfg.args();
        let i = args
            .iter()
            .position(|a| a == "--__OwningControllerProcess")
            .expect("tor would outlive krab");
        assert_eq!(args[i + 1], std::process::id().to_string());
    }

    /// Ports are ephemeral, not fixed — two nodes on one host must not
    /// collide, and a predictable control port is a predictable target.
    #[test]
    fn both_ports_are_ephemeral() {
        let args = TorLaunch::on_path(tmp("ports")).args();
        for flag in ["--SocksPort", "--ControlPort"] {
            let i = args.iter().position(|a| a == flag).unwrap();
            assert_eq!(args[i + 1], "auto", "{flag} must not be a fixed port");
        }
    }

    /// Bootstrap parsing, including the shapes tor actually emits.
    #[test]
    fn bootstrap_progress_is_parsed() {
        let b = Bootstrap::parse(
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 \
             TAG=requesting_descriptors SUMMARY=\"Asking for relay descriptors\"\r\n250 OK\r\n",
        );
        assert_eq!(b.percent, 45);
        assert_eq!(b.summary, "Asking for relay descriptors");
        assert!(!b.is_done());

        let done = Bootstrap::parse(
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done \
             SUMMARY=\"Done\"\r\n250 OK\r\n",
        );
        assert!(done.is_done());
    }

    /// **A reply tor phrases unexpectedly must not be an error.** This is
    /// polled on the interface tick; returning `Err` for a cosmetic reason
    /// would take the node down over a progress indicator.
    #[test]
    fn unparseable_bootstrap_is_zero_rather_than_an_error() {
        let b = Bootstrap::parse("250 OK\r\n");
        assert_eq!(b.percent, 0);
        assert_eq!(b.summary, "starting");
    }

    /// `overwrite` clears the buffer that held the onion key.
    #[test]
    fn the_key_carrying_command_is_overwritten() {
        let mut s = String::from("ADD_ONION ED25519-V3:c2VjcmV0 Flags=DiscardPK");
        let cap = s.capacity();
        overwrite(&mut s);
        assert!(s.is_empty());
        assert_eq!(
            s.capacity(),
            cap,
            "the allocation was replaced, not cleared"
        );
    }

    /// Shredding overwrites and removes, and is quiet about a file that has
    /// already gone — `stop` is idempotent and calls it twice.
    #[test]
    fn shredding_removes_and_tolerates_absence() {
        let dir = tmp("shred");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("cookie");
        std::fs::write(&f, [9u8; 32]).unwrap();
        shred(&f).unwrap();
        assert!(!f.exists());
        shred(&f).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x00, 0xa5, 0xff]), "00a5ff");
    }

    /// **The whole launch path, against a real tor — when there is one.**
    ///
    /// Everything else in this module tests argument construction and reply
    /// parsing, which is to say it tests what Krab *says* rather than whether
    /// tor accepts it. This is the only test that finds out, and the two are
    /// not close: an argument tor rejects, a control protocol phrased
    /// differently, a cookie file written somewhere else would all pass every
    /// other test here and fail at the first real start.
    ///
    /// It **skips** rather than fails when tor is absent, because a developer
    /// without tor installed should not have a red suite — but it does not
    /// skip silently on a machine that has it. Run `cargo test -- --nocapture`
    /// to see which branch was taken.
    ///
    /// Not marked `#[ignore]`: an ignored test is one nobody runs, and this is
    /// the one worth running most.
    #[test]
    fn a_real_tor_starts_authenticates_and_reports_a_socks_port() {
        // Resolve without a shell: `Command::new("tor")` uses the same PATH
        // lookup the production path does, so this probes exactly what
        // `TorLaunch::on_path` would get.
        let present = Command::new("tor")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        if !present {
            println!("skipped: no `tor` on PATH");
            return;
        }

        let dir = tmp("live");
        let cfg = TorLaunch::on_path(&dir);
        let mut tor = match TorProcess::launch(&cfg) {
            Ok(t) => t,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                panic!("tor is installed but krab could not drive it: {e}");
            }
        };

        assert!(tor.socks_port() != 0, "no SOCKS port was reported");
        assert!(tor.is_running());

        // Bootstrap is polled, not waited on — this asserts the query works,
        // not that the network is reachable, so it passes offline.
        let b = tor.bootstrap().expect("bootstrap query failed");
        println!(
            "live tor: binary={} socks={} bootstrap={}% {}",
            tor.binary(),
            tor.socks_port(),
            b.percent,
            b.summary
        );

        // The empty torrc really was what tor read: if it had picked up a
        // system config with a fixed SocksPort, `auto` would not have been
        // honoured and the port would be that one. Not conclusive alone, but
        // it is the observable consequence.
        assert_ne!(
            tor.socks_port(),
            9050,
            "tor appears to have read a system torrc"
        );

        tor.stop();
        assert!(!tor.is_running(), "stop did not kill the daemon");
        assert!(
            !dir.join(COOKIE_FILE).exists(),
            "the control cookie survived stop"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The reader stops at the line with a *space* after the status code,
    /// not at the first line beginning `250`.**
    ///
    /// This is the one that would corrupt everything downstream. `ADD_ONION`
    /// answers with `250-ServiceID=…` then `250 OK`; a reader that returned at
    /// the first `250` would leave `250 OK` in the socket, and the *next*
    /// command would read it as its own reply. Every subsequent exchange would
    /// then be answering the previous question — and the first symptom would
    /// be a `GETINFO` that returned `OK`, which parses as no SOCKS port.
    #[test]
    fn a_multi_line_reply_is_read_to_its_final_line() {
        let mut r = std::io::Cursor::new(
            "250-ServiceID=abcdefghij\r\n250-PrivateKey=x\r\n250 OK\r\nLEFTOVER\r\n"
                .as_bytes()
                .to_vec(),
        );
        let body = read_reply_from(&mut r).unwrap();
        assert!(body.contains("ServiceID=abcdefghij"));
        assert!(body.contains("250 OK"));
        assert!(!body.contains("LEFTOVER"), "read past the end of the reply");
    }

    /// A non-2xx final line is an error carrying tor's own words, which are
    /// more useful than any paraphrase.
    #[test]
    fn a_refusal_carries_tors_text() {
        let mut r = std::io::Cursor::new("512 Invalid key type\r\n".as_bytes().to_vec());
        match read_reply_from(&mut r) {
            Err(TorError::Control(s)) => assert!(s.contains("Invalid key type"), "{s}"),
            other => panic!("expected a control error, got {other:?}"),
        }
    }

    /// A closed port is an error rather than an empty success — otherwise a
    /// dead daemon reads as a daemon that answered nothing.
    #[test]
    fn a_closed_control_port_is_an_error() {
        let mut r = std::io::Cursor::new(Vec::new());
        assert!(matches!(read_reply_from(&mut r), Err(TorError::Control(_))));
    }

    /// **The onion name goes to tor, not to the resolver.**
    ///
    /// This is the defect the type exists to close. Before `TorFabric`,
    /// `connect <peer> tor <addr>` fell through to the TCP branch, and
    /// `TcpStream::connect` hands a hostname to the system resolver — so the
    /// dial failed *and* told the operator's DNS server which hidden service
    /// this node was looking for. A test that only checked "connect returns an
    /// error" would have passed on the broken version.
    #[test]
    fn an_onion_link_dials_through_socks_and_never_resolves_the_name() {
        use std::io::Read;
        let onion = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();

        // Bounded, because the failure this test is guarding against is a
        // dial that never reaches the proxy at all — and a blocking `accept`
        // would turn that into a hung test binary rather than a red one. The
        // socks helper learned this the same way.
        l.set_nonblocking(true).unwrap();
        let h = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut s = loop {
                match l.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Vec::new();
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return Vec::new(),
                }
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).unwrap();
            // Version 5, no authentication.
            s.write_all(&[0x05, 0x00]).unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            s.read_exact(&mut rest).unwrap();
            let mut seen = head.to_vec();
            seen.extend_from_slice(&rest);
            // Succeed, then say nothing: the handshake that follows is not
            // what this test is about.
            let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            seen
        });

        let f = TorFabric::new(
            crate::profile::LinkProfile::tor(),
            port,
            onion,
            [7u8; 32],
            [9u8; 32],
        );
        // The handshake cannot complete against a socket that says nothing,
        // so this fails — after the part being measured has already happened.
        let _ = crate::Fabric::connect(&f);

        let sent = h.join().unwrap();
        assert!(
            !sent.is_empty(),
            "nothing reached the SOCKS port — the dial went somewhere else, \
             which for a hostname means the system resolver"
        );
        assert_eq!(sent[0], 0x05, "SOCKS5");
        assert_eq!(sent[1], 0x01, "CONNECT");
        assert_eq!(
            sent[3], 0x03,
            "the address type must be DOMAIN — an IP type means the name was resolved here"
        );
        assert_eq!(sent[4] as usize, onion.len());
        assert_eq!(&sent[5..5 + onion.len()], onion.as_bytes());
        assert_eq!(
            u16::from_be_bytes([sent[5 + onion.len()], sent[6 + onion.len()]]),
            ONION_PORT
        );
    }

    /// **A tor link never accepts.** Inbound arrives at the listener the onion
    /// service forwards to. A fabric that also accepted would be a second
    /// listener racing the first for the same connections.
    #[test]
    fn a_tor_link_is_outbound_only() {
        let f = TorFabric::new(
            crate::profile::LinkProfile::tor(),
            1,
            "x.onion",
            [1u8; 32],
            [2u8; 32],
        );
        assert!(crate::Fabric::accept(&f).unwrap().is_none());
    }

    /// No tor running is an ordinary error, not a hang — I-4 again.
    #[test]
    fn a_dead_socks_port_is_an_error() {
        let f = TorFabric::new(
            crate::profile::LinkProfile::tor(),
            // Port 1 on loopback: reserved, nothing listening.
            1,
            "x.onion",
            [1u8; 32],
            [2u8; 32],
        );
        assert!(crate::Fabric::connect(&f).is_err());
    }
}
