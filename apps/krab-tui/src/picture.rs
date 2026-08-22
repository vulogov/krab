//! Pictures — RFC 8 §6. Decode, cap, re-encode; never validate.
//!
//! ```text
//! The client MUST NOT validate an image. It MUST decode and re-encode it,
//! and MUST transmit the re-encoded bytes.
//! ```
//!
//! # Why validation does not work
//!
//! **Polyglot files** are simultaneously a valid PNG and a valid ZIP, or a
//! valid GIF and a valid JAR. They pass every magic-byte check ever written,
//! because they genuinely are images. And a genuine image is not safe either:
//! image parsers are historically the richest source of remote code execution,
//! so **the decoder is the attack surface** and a check that runs before it
//! protects nothing.
//!
//! Re-encoding gives four properties at once, and none of them are opt-in:
//!
//! - Polyglots die. The output holds pixel data this program generated.
//! - **EXIF dies, including GPS.** A photograph carrying a location would be a
//!   catastrophic metadata leak in a system otherwise this careful, so RFC 8
//!   §6 requires stripping be automatic and **MUST NOT be offered as a
//!   setting**. There is accordingly no argument here that disables it.
//! - Trailing data, ICC profiles and container steganography die with it.
//! - Sizes normalise, which feeds RFC 1 §8.1's bucket padding.
//!
//! # The cap comes before the allocation
//!
//! ```text
//! Pixel count MUST be capped from the header before allocation.
//! ```
//!
//! A decompression bomb is the failure a size limit misses: 100 KB of PNG
//! expanding to 50 GB. So the dimensions are read from the header and checked
//! *before* any decoder is asked for pixels — [`dimensions`] is deliberately
//! a separate function from [`transcode`], and the cap is applied between
//! them.
//!
//! # Isolation
//!
//! ```text
//! Decoding SHOULD occur in a separate process; where it does not, it MUST
//!   occur on a task isolated from key material.
//! ```
//!
//! This module is the isolation: it is a pure function from bytes to bytes. It
//! holds no identity, no epoch key, no store handle, and cannot reach one —
//! there is nothing in scope to reach. `crate::main` runs it on its own
//! thread, which receives a `Vec<u8>` and returns a `Vec<u8>`.
//!
//! A separate *process* would be stronger and is not done. That is a real gap
//! and it is recorded here rather than in a footnote: a decoder bug that
//! achieves code execution owns the address space, and this program's address
//! space contains the unlocked corpus key.

use png::{BitDepth, ColorType};

/// The most pixels this program will decode.
///
/// **A memory bound, not a quality setting.** At 4 bytes per pixel this caps a
/// decoded image at 4 MiB, which is the largest allocation a picture may cause
/// on any node — including one running on a phone or a router.
///
/// It is generous relative to what can actually be sent: a picture must
/// re-encode into RFC 1 §8.1's largest bucket, 262 144 bytes, and no
/// photograph at a megapixel does. The object-size limit binds long before
/// this one, and this exists solely to stop a decompression bomb between the
/// header and the pixels.
pub const MAX_PIXELS: u64 = 1024 * 1024;

/// The largest object RFC 1 §8.1 defines, and therefore the most a picture may
/// occupy once re-encoded.
pub const MAX_OBJECT: usize = 262_144;

/// Marks a sealed plaintext as a picture rather than text.
///
/// **Inside the ciphertext**, so it is as confidential as the picture itself.
/// A class byte in the routing header would tell every relay which messages
/// are pictures, and message *kind* is exactly the metadata RFC 1 §5 keeps out
/// of the header.
pub const MARKER: &[u8] = b"krab/pic/v1\n";

/// Split a decrypted plaintext into a picture, if it is one.
pub fn from_plaintext(plain: &[u8]) -> Option<&[u8]> {
    plain.strip_prefix(MARKER)
}

/// Why a picture was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not a format this program decodes.
    ///
    /// Deliberately not "not an image": this program's opinion about what a
    /// file *is* has no security value, and the list is what it can decode.
    Unsupported,
    /// The header declares more pixels than [`MAX_PIXELS`].
    ///
    /// Refused **before** the decoder allocates, which is the whole point.
    TooManyPixels { declared: u64 },
    /// The decoder refused it. Includes files that are the right shape and
    /// wrong inside.
    Corrupt,
    /// Re-encoded, and larger than one object can hold.
    TooLarge { bytes: usize },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Unsupported => f.write_str(
                "not a PNG or JPEG. Those are the two this program can decode, \
                 and it will not forward bytes it did not produce.",
            ),
            Error::TooManyPixels { declared } => write!(
                f,
                "the header declares {declared} pixels; the limit is {MAX_PIXELS}. \
                 Refused before decoding — a 100 KB file can declare 50 GB of \
                 pixels, and the limit is what stops it."
            ),
            Error::Corrupt => f.write_str("the decoder refused it"),
            Error::TooLarge { bytes } => write!(
                f,
                "re-encoded to {bytes} bytes, and the largest object is {MAX_OBJECT}. \
                 Scale the picture down and try again."
            ),
        }
    }
}

/// What the header says, without decoding anything.
///
/// **Header only.** The point is to learn the size before committing memory to
/// the pixels, so this must not be merged into `transcode` however convenient
/// that would be.
pub fn dimensions(bytes: &[u8]) -> Result<(u32, u32), Error> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        // The IHDR is the first chunk and carries the dimensions, so the
        // decoder reads a fixed prefix and stops.
        let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
        let reader = decoder.read_info().map_err(|_| Error::Corrupt)?;
        let info = reader.info();
        return Ok((info.width, info.height));
    }
    if bytes.starts_with(&[0xFF, 0xD8]) {
        let mut d = zune_jpeg::JpegDecoder::new(std::io::Cursor::new(bytes));
        d.decode_headers().map_err(|_| Error::Corrupt)?;
        let (w, h) = d.dimensions().ok_or(Error::Corrupt)?;
        return Ok((w as u32, h as u32));
    }
    Err(Error::Unsupported)
}

/// Decode, cap, and re-encode to canonical PNG.
///
/// The returned bytes are the only ones that may be transmitted. RFC 8 §6:
/// *"It MUST transmit the re-encoded bytes."*
pub fn transcode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    // 1. The cap, from the header, before anything allocates pixels.
    let (w, h) = dimensions(bytes)?;
    let declared = u64::from(w) * u64::from(h);
    if declared > MAX_PIXELS || declared == 0 {
        return Err(Error::TooManyPixels { declared });
    }

    // 2. Decode to RGBA8. One shape out of every decoder, so the encoder has
    //    one case and there is no path where a format's quirk survives.
    let (rgba, w, h) = if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        decode_png(bytes)?
    } else {
        decode_jpeg(bytes)?
    };

    // The decoder's own view must agree with the header's. A decoder that
    // produced more pixels than the header declared would have escaped the
    // cap entirely.
    if u64::from(w) * u64::from(h) > MAX_PIXELS || rgba.len() != (w as usize) * (h as usize) * 4 {
        return Err(Error::Corrupt);
    }

    // 3. Re-encode. Nothing from the input reaches the output but pixels:
    //    no EXIF, no ICC, no trailing bytes, no ancillary chunks.
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(ColorType::Rgba);
        enc.set_depth(BitDepth::Eight);
        let mut writer = enc.write_header().map_err(|_| Error::Corrupt)?;
        writer.write_image_data(&rgba).map_err(|_| Error::Corrupt)?;
    }
    if out.len() > MAX_OBJECT {
        return Err(Error::TooLarge { bytes: out.len() });
    }
    Ok(out)
}

fn decode_png(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32), Error> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|_| Error::Corrupt)?;
    let mut buf = vec![0; reader.output_buffer_size().ok_or(Error::Corrupt)?];
    let info = reader.next_frame(&mut buf).map_err(|_| Error::Corrupt)?;
    let (w, h) = (info.width, info.height);
    let px = (w as usize) * (h as usize);

    // Every input colour type becomes RGBA8, so the encoder has one case.
    let rgba = match info.color_type {
        ColorType::Rgba => buf[..px * 4].to_vec(),
        ColorType::Rgb => buf[..px * 3]
            .chunks_exact(3)
            .flat_map(|c| [c[0], c[1], c[2], 0xff])
            .collect(),
        ColorType::Grayscale => buf[..px].iter().flat_map(|&g| [g, g, g, 0xff]).collect(),
        ColorType::GrayscaleAlpha => buf[..px * 2]
            .chunks_exact(2)
            .flat_map(|c| [c[0], c[0], c[0], c[1]])
            .collect(),
        // Indexed is normalised away by the transformation above; anything
        // else is a format this build does not know, and guessing is how a
        // decoder grows an attack surface.
        _ => return Err(Error::Corrupt),
    };
    Ok((rgba, w, h))
}

fn decode_jpeg(bytes: &[u8]) -> Result<(Vec<u8>, u32, u32), Error> {
    let mut d = zune_jpeg::JpegDecoder::new(std::io::Cursor::new(bytes));
    d.decode_headers().map_err(|_| Error::Corrupt)?;
    let (w, h) = d.dimensions().ok_or(Error::Corrupt)?;
    let px = w * h;
    let pixels = d.decode().map_err(|_| Error::Corrupt)?;

    // zune yields RGB or luma depending on the file.
    let rgba = match pixels.len().checked_div(px) {
        Some(3) => pixels
            .chunks_exact(3)
            .flat_map(|c| [c[0], c[1], c[2], 0xff])
            .collect(),
        Some(1) => pixels.iter().flat_map(|&g| [g, g, g, 0xff]).collect(),
        Some(4) => pixels,
        _ => return Err(Error::Corrupt),
    };
    Ok((rgba, w as u32, h as u32))
}

/// One character cell of a rendered picture: two vertically-stacked pixels.
pub type Cell = ([u8; 3], [u8; 3]);

/// One rendered row.
pub type Cell2 = Vec<Cell>;

/// Decode a picture and reduce it to character cells for the terminal.
///
/// # Why this renders pixels itself rather than using a terminal protocol
///
/// Kitty, iTerm2 and sixel all exist, and all of them work by **handing the
/// encoded image to the terminal emulator**, which decodes it. Kitty's
/// protocol takes a PNG directly.
///
/// That is the thing RFC 8 §6 forbids:
///
/// ```text
/// The client MUST NOT pass received bytes to a system image viewer.
/// ```
///
/// A terminal emulator running someone else's PNG through its own decoder is
/// a system image viewer. It sits outside every boundary this program
/// maintains, it is a different codebase with different bugs, and the file
/// came from whoever sent it.
///
/// So the pixels are decoded *here*, by the decoder already audited for this
/// purpose, and what reaches the terminal is characters and colours — the
/// same thing every other pane emits. There is no image on the wire to the
/// terminal at all.
///
/// (If a graphics protocol were ever used, it would have to be with **raw RGB**
/// rather than PNG, for exactly this reason. That is worth writing down
/// because "just use kitty" is the obvious suggestion and it quietly
/// reintroduces the decoder.)
///
/// # The half-block trick
///
/// A character cell is about twice as tall as it is wide, so one cell carries
/// two pixels: `▀` with the *foreground* set to the upper pixel and the
/// *background* to the lower. That doubles vertical resolution for free and
/// needs nothing but colour, which every terminal in use has.
pub fn cells(png: &[u8], max_cols: u32, max_rows: u32) -> Result<Vec<Vec<Cell>>, Error> {
    let (w, h) = dimensions(png)?;
    let declared = u64::from(w) * u64::from(h);
    if declared > MAX_PIXELS || declared == 0 {
        return Err(Error::TooManyPixels { declared });
    }
    let (rgba, w, h) = if png.starts_with(&[0x89, b'P', b'N', b'G']) {
        decode_png(png)?
    } else {
        decode_jpeg(png)?
    };
    if rgba.len() != (w as usize) * (h as usize) * 4 {
        return Err(Error::Corrupt);
    }
    if max_cols == 0 || max_rows == 0 {
        return Ok(Vec::new());
    }

    // Two pixels per row of cells.
    let out_w = max_cols.min(w).max(1);
    let out_h = (max_rows * 2).min(h).max(2);
    // Preserve the aspect ratio, remembering a cell is twice as tall as wide.
    let scale = ((w as f32 / out_w as f32).max(h as f32 / out_h as f32)).max(1.0);
    let out_w = ((w as f32 / scale) as u32).clamp(1, max_cols);
    let out_h = ((h as f32 / scale) as u32).clamp(2, max_rows * 2);

    let at = |x: u32, y: u32| -> [u8; 3] {
        // Nearest neighbour. Sampling quality is not a security property and a
        // box filter here would be a second loop over attacker-sized data.
        let sx = ((x as u64 * w as u64) / out_w as u64).min(w as u64 - 1) as usize;
        let sy = ((y as u64 * h as u64) / out_h as u64).min(h as u64 - 1) as usize;
        let i = (sy * w as usize + sx) * 4;
        [rgba[i], rgba[i + 1], rgba[i + 2]]
    };

    let mut rows = Vec::with_capacity((out_h / 2) as usize);
    for cy in 0..out_h / 2 {
        let mut row = Vec::with_capacity(out_w as usize);
        for cx in 0..out_w {
            row.push((at(cx, cy * 2), at(cx, cy * 2 + 1)));
        }
        rows.push(row);
    }
    Ok(rows)
}

/// Whether the terminal can show a picture at all.
///
/// Reads `COLORTERM`, which is how terminals advertise 24-bit colour. This is
/// the one place the interface consults the environment, and it is not a
/// contradiction of `NO-CONFIG.md`'s rule: that rule is about *decisions* —
/// what this node does, who it talks to — which must come from the operator
/// and never from an inherited variable. This is a *capability*, and getting
/// it wrong produces bad colours rather than a bad security outcome.
pub fn terminal_supports_colour(colorterm: Option<&str>) -> bool {
    matches!(colorterm, Some(v) if v.eq_ignore_ascii_case("truecolor") || v == "24bit")
}

/// Whether a link can carry a picture at all — RFC 4 §5.4.
///
/// RFC 8 §6: *"Pictures cannot cross LoRa links. The client MUST say so
/// before sending, not after silent non-delivery."*
pub fn carriable(profile: &krab_fabric::profile::LinkProfile) -> bool {
    profile.kind != "lora"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal well-formed PNG of `w`×`h`, built by the encoder this module
    /// also uses — so the tests exercise the pipeline rather than a fixture.
    fn png_of(w: u32, h: u32) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(ColorType::Rgba);
            enc.set_depth(BitDepth::Eight);
            let mut wr = enc.write_header().unwrap();
            wr.write_image_data(&vec![0x40; (w as usize) * (h as usize) * 4])
                .unwrap();
        }
        out
    }

    #[test]
    fn a_picture_round_trips_through_the_pipeline() {
        let out = transcode(&png_of(8, 8)).expect("transcodes");
        assert_eq!(dimensions(&out).unwrap(), (8, 8));
        // The output is itself acceptable input, so a forward is a re-encode
        // rather than a pass-through.
        assert!(transcode(&out).is_ok());
    }

    /// **The cap is applied before the decoder allocates.** This is the whole
    /// defence against a decompression bomb: a small file declaring an
    /// enormous canvas.
    #[test]
    fn an_oversized_canvas_is_refused_from_the_header() {
        // A header claiming 40 000 × 40 000 = 1.6e9 pixels. The file itself is
        // tiny; decoding it would ask for six gigabytes.
        let mut bomb = png_of(1, 1);
        // Patch IHDR's width and height in place, then fix its CRC.
        let ihdr = 12; // 8-byte signature + 4-byte length
        bomb[ihdr + 4..ihdr + 8].copy_from_slice(&40_000u32.to_be_bytes());
        bomb[ihdr + 8..ihdr + 12].copy_from_slice(&40_000u32.to_be_bytes());
        let crc = crc32fast::hash(&bomb[ihdr..ihdr + 17]);
        bomb[ihdr + 17..ihdr + 21].copy_from_slice(&crc.to_be_bytes());

        assert_eq!(dimensions(&bomb).unwrap(), (40_000, 40_000));
        match transcode(&bomb) {
            Err(Error::TooManyPixels { declared }) => {
                assert_eq!(declared, 40_000u64 * 40_000)
            }
            other => panic!("a decompression bomb was not refused: {other:?}"),
        }
    }

    /// The limit is exact, and a zero-pixel image is not a picture.
    #[test]
    fn the_cap_is_where_it_says_it_is() {
        assert!(u64::from(1024u32) * 1024 == MAX_PIXELS);
        // One pixel over, from the header, without building the file.
        let mut over = png_of(1, 1);
        let ihdr = 12;
        over[ihdr + 4..ihdr + 8].copy_from_slice(&1025u32.to_be_bytes());
        over[ihdr + 8..ihdr + 12].copy_from_slice(&1024u32.to_be_bytes());
        let crc = crc32fast::hash(&over[ihdr..ihdr + 17]);
        over[ihdr + 17..ihdr + 21].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(transcode(&over), Err(Error::TooManyPixels { .. })));
    }

    /// **Polyglots die.** A file that is a valid PNG *and* carries an
    /// appended archive passes every magic-byte check, because it genuinely is
    /// a PNG. What survives re-encoding is the pixels.
    #[test]
    fn appended_data_does_not_survive() {
        let mut polyglot = png_of(4, 4);
        polyglot.extend_from_slice(b"PK\\x03\\x04 a whole zip archive lives here");
        let marker = b"a whole zip archive";

        let out = transcode(&polyglot).expect("it is a valid PNG, so it decodes");
        assert!(
            !out.windows(marker.len()).any(|w| w == marker),
            "appended data survived the pipeline"
        );
    }

    /// **EXIF dies, and stripping is not a setting.** RFC 8 §6 makes it
    /// automatic precisely because a GPS coordinate in a photograph would be
    /// catastrophic in a system otherwise this careful.
    #[test]
    fn ancillary_chunks_do_not_survive() {
        // A PNG carrying a tEXt chunk — the same position an eXIf chunk
        // occupies, and easier to construct.
        let base = png_of(4, 4);
        let mut with_text = Vec::new();
        with_text.extend_from_slice(&base[..33]); // signature + IHDR
        let payload = b"CommentGPS 51.5074 -0.1278";
        with_text.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        with_text.extend_from_slice(b"tEXt");
        with_text.extend_from_slice(payload);
        let mut crc_input = b"tEXt".to_vec();
        crc_input.extend_from_slice(payload);
        with_text.extend_from_slice(&crc32fast::hash(&crc_input).to_be_bytes());
        with_text.extend_from_slice(&base[33..]);

        assert!(
            with_text.windows(3).any(|w| w == b"GPS"),
            "the fixture does not contain what the test is about"
        );
        let out = transcode(&with_text).expect("transcodes");
        assert!(
            !out.windows(3).any(|w| w == b"GPS"),
            "metadata survived the pipeline — this is the GPS leak RFC 8 §6 \
             exists to prevent"
        );
    }

    /// Anything the decoders do not handle is refused rather than forwarded.
    /// This program does not have an opinion about what a file *is*; it has a
    /// list of what it can decode.
    #[test]
    fn unknown_formats_are_refused_and_never_forwarded() {
        for junk in [
            &b"GIF89a"[..],
            &b"%PDF-1.7"[..],
            &b"<svg xmlns=http://www.w3.org/2000/svg>"[..],
            &[0x7f, b'E', b'L', b'F'][..],
            &[][..],
        ] {
            assert_eq!(transcode(junk), Err(Error::Unsupported), "{junk:?}");
        }
    }

    /// A file with the right magic bytes and rubbish inside is the decoder's
    /// problem, and the decoder must fail rather than the process.
    #[test]
    fn corrupt_input_is_refused_without_panicking() {
        let good = png_of(8, 8);
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = transcode(&bad);
        }
        for cut in 0..good.len() {
            let _ = transcode(&good[..cut]);
        }
        // And a JPEG magic with nothing behind it.
        assert!(transcode(&[0xFF, 0xD8, 0x00, 0x00]).is_err());
    }

    /// A picture that will not fit in one object is refused with the reason,
    /// rather than being sent as something that cannot be reassembled.
    #[test]
    fn a_picture_too_large_for_one_object_is_refused() {
        // Random pixels do not compress, so this exceeds the bucket while
        // staying well inside the pixel cap.
        let (w, h) = (512u32, 512u32);
        let mut noise = Vec::with_capacity((w * h * 4) as usize);
        let mut x = 0x1234_5678u32;
        for _ in 0..(w * h * 4) {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            noise.push((x >> 24) as u8);
        }
        let mut src = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut src, w, h);
            enc.set_color(ColorType::Rgba);
            enc.set_depth(BitDepth::Eight);
            let mut wr = enc.write_header().unwrap();
            wr.write_image_data(&noise).unwrap();
        }
        match transcode(&src) {
            Err(Error::TooLarge { bytes }) => assert!(bytes > MAX_OBJECT),
            other => panic!("expected a size refusal, got {other:?}"),
        }
    }

    /// **RFC 4 §5.4** — and RFC 8 §6 requires saying so *before* sending,
    /// not after silent non-delivery.
    #[test]
    fn a_lora_link_cannot_carry_a_picture() {
        use krab_fabric::profile::LinkProfile;
        assert!(!carriable(&LinkProfile::lora_sf10()));
        assert!(carriable(&LinkProfile::tcp()));
        assert!(carriable(&LinkProfile::serial()));
        assert!(carriable(&LinkProfile::courier()));
    }

    /// Every error says what to do, because a refusal an operator cannot act
    /// on is a refusal they will work around.
    #[test]
    fn every_refusal_is_actionable() {
        assert!(Error::Unsupported.to_string().contains("PNG or JPEG"));
        assert!(Error::TooManyPixels { declared: 9 }
            .to_string()
            .contains("Refused before decoding"));
        assert!(Error::TooLarge { bytes: 9 }
            .to_string()
            .contains("Scale the picture down"));
    }

    /// A picture becomes character cells, within the space it was given, with
    /// its aspect ratio intact.
    #[test]
    fn a_picture_reduces_to_cells_that_fit() {
        let src = png_of(64, 32);
        let rows = cells(&src, 20, 20).expect("renders");
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|r| r.len() <= 20), "too wide");
        assert!(rows.len() <= 20, "too tall");
        // Every row is the same width, or the pane would look ragged.
        let w = rows[0].len();
        assert!(rows.iter().all(|r| r.len() == w));
        // Wider than tall in, wider than tall out — a cell is two pixels high.
        assert!(
            w > rows.len(),
            "the aspect ratio was lost: {w}×{}",
            rows.len()
        );
    }

    /// **The pixel cap applies to display too.** A bomb that could not be
    /// *sent* must not be decodable by *viewing* it either — a received object
    /// arrives from the network, not from the operator's disk.
    #[test]
    fn rendering_a_bomb_is_refused_before_decoding() {
        let mut bomb = png_of(1, 1);
        let ihdr = 12;
        bomb[ihdr + 4..ihdr + 8].copy_from_slice(&40_000u32.to_be_bytes());
        bomb[ihdr + 8..ihdr + 12].copy_from_slice(&40_000u32.to_be_bytes());
        let crc = crc32fast::hash(&bomb[ihdr..ihdr + 17]);
        bomb[ihdr + 17..ihdr + 21].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(
            cells(&bomb, 40, 20),
            Err(Error::TooManyPixels { .. })
        ));
    }

    /// A pane with no room yields nothing rather than dividing by zero.
    #[test]
    fn no_room_renders_nothing() {
        let src = png_of(16, 16);
        assert!(cells(&src, 0, 10).unwrap().is_empty());
        assert!(cells(&src, 10, 0).unwrap().is_empty());
    }

    /// Colour is a capability, read from the environment because that is where
    /// terminals advertise it — and getting it wrong costs colours, not
    /// security.
    #[test]
    fn colour_support_is_detected_conservatively() {
        assert!(terminal_supports_colour(Some("truecolor")));
        assert!(terminal_supports_colour(Some("TrueColor")));
        assert!(terminal_supports_colour(Some("24bit")));
        assert!(!terminal_supports_colour(Some("")));
        assert!(!terminal_supports_colour(Some("16")));
        assert!(!terminal_supports_colour(None));
    }

    /// Nothing an attacker sends causes a panic while being *looked at*.
    #[test]
    fn rendering_corrupt_input_does_not_panic() {
        let good = png_of(8, 8);
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = cells(&bad, 40, 20);
        }
        for cut in 0..good.len() {
            let _ = cells(&good[..cut], 40, 20);
        }
    }
}
