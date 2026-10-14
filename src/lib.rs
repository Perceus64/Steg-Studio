//! Steganography Studio — an educational tool for a cybersecurity club.
//!
//! It hides a payload in the least-significant bits (LSBs) of an image's
//! RGB channels, after encrypting that payload with AES-256-GCM using a
//! key derived from a password. It can also run a basic steganalysis pass
//! that estimates how "suspicious" an image's LSBs look.
//!
//! This is a teaching demo. LSB steganography is trivially destroyed by
//! re-saving as JPEG and is detectable by the very analysis included here —
//! those facts are the lesson, not a limitation to hide.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

const MAGIC: &[u8; 4] = b"STG1";
const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Cryptography
// ---------------------------------------------------------------------------

/// Derives a 32-byte AES key from a password (SHA-256).
fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Encrypts `plaintext`, returning `nonce || ciphertext` (ciphertext carries
/// the GCM authentication tag).
fn encrypt(password: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let key_bytes = derive_key(password);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| format!("rng error: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "encryption failed".to_string())?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reverses [`encrypt`]. A wrong password fails the GCM tag check, so this
/// returns an error rather than garbage.
fn decrypt(password: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < NONCE_LEN {
        return Err("data too short".to_string());
    }
    let key_bytes = derive_key(password);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "wrong password or the image has no hidden data".to_string())
}

// ---------------------------------------------------------------------------
// LSB embedding
// ---------------------------------------------------------------------------

/// Bits of payload capacity in an RGBA buffer (3 usable channels per pixel).
fn capacity_bits(rgba_len: usize) -> usize {
    (rgba_len / 4) * 3
}

/// Usable payload size in bytes, after the length header is accounted for.
fn capacity_bytes(rgba_len: usize) -> usize {
    let frame = (MAGIC.len() + 4) * 8; // magic + u32 length
    capacity_bits(rgba_len).saturating_sub(frame) / 8
}

/// Maps the Nth embedded bit to an index into the RGBA buffer, skipping the
/// alpha channel of every pixel.
fn channel_index(bit: usize) -> usize {
    (bit / 3) * 4 + (bit % 3)
}

/// Writes `data` into the LSBs of `rgba` in place. Layout: MAGIC, then the
/// payload length as a big-endian u32, then the payload itself.
fn embed(rgba: &mut [u8], data: &[u8]) -> Result<(), String> {
    let mut framed = Vec::with_capacity(MAGIC.len() + 4 + data.len());
    framed.extend_from_slice(MAGIC);
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(data);

    if framed.len() * 8 > capacity_bits(rgba.len()) {
        return Err(format!(
            "payload too large: need {} bytes of capacity, image holds {}",
            framed.len(),
            capacity_bytes(rgba.len()) + MAGIC.len() + 4
        ));
    }

    for (i, byte) in framed.iter().enumerate() {
        for b in 0..8 {
            let bit = (byte >> (7 - b)) & 1; // most-significant bit first
            let idx = channel_index(i * 8 + b);
            rgba[idx] = (rgba[idx] & 0xFE) | bit;
        }
    }
    Ok(())
}

/// Reads one byte out of the LSBs starting at bit position `start`.
fn read_byte(rgba: &[u8], start: usize) -> u8 {
    let mut byte = 0u8;
    for b in 0..8 {
        byte = (byte << 1) | (rgba[channel_index(start + b)] & 1);
    }
    byte
}

/// Recovers the embedded payload, or an error if no valid header is present.
fn extract(rgba: &[u8]) -> Result<Vec<u8>, String> {
    let cap = capacity_bits(rgba.len());
    if cap < (MAGIC.len() + 4) * 8 {
        return Err("image too small to contain data".to_string());
    }

    for (i, m) in MAGIC.iter().enumerate() {
        if read_byte(rgba, i * 8) != *m {
            return Err("no hidden data found (bad signature)".to_string());
        }
    }

    let mut len_bytes = [0u8; 4];
    for (i, lb) in len_bytes.iter_mut().enumerate() {
        *lb = read_byte(rgba, (MAGIC.len() + i) * 8);
    }
    let len = u32::from_be_bytes(len_bytes) as usize;

    let header = MAGIC.len() + 4;
    if (header + len) * 8 > cap {
        return Err("declared length exceeds image capacity".to_string());
    }

    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(read_byte(rgba, (header + i) * 8));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Steganalysis
// ---------------------------------------------------------------------------

/// A rough "how suspicious are these LSBs" report.
#[wasm_bindgen]
pub struct Analysis {
    capacity_bytes: usize,
    lsb_ratio: f64,
    chi_square: f64,
    has_signature: bool,
}

#[wasm_bindgen]
impl Analysis {
    #[wasm_bindgen(getter)]
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
    /// Fraction of LSBs set to 1. Natural images sit near 0.5 already, so on
    /// its own this is weak — it's shown to make the point.
    #[wasm_bindgen(getter)]
    pub fn lsb_ratio(&self) -> f64 {
        self.lsb_ratio
    }
    /// Chi-square on adjacent value pairs (2k, 2k+1). Embedded data pushes
    /// each pair toward 50/50, driving this statistic down.
    #[wasm_bindgen(getter)]
    pub fn chi_square(&self) -> f64 {
        self.chi_square
    }
    /// Whether our own STG1 signature is present.
    #[wasm_bindgen(getter)]
    pub fn has_signature(&self) -> bool {
        self.has_signature
    }
}

fn analyze_bytes(rgba: &[u8]) -> Analysis {
    // LSB ratio across RGB channels.
    let mut ones = 0usize;
    let mut total = 0usize;
    // Histogram of channel values for the chi-square test.
    let mut hist = [0u64; 256];

    for px in rgba.chunks_exact(4) {
        for &c in &px[0..3] {
            ones += (c & 1) as usize;
            total += 1;
            hist[c as usize] += 1;
        }
    }

    let lsb_ratio = if total > 0 { ones as f64 / total as f64 } else { 0.0 };

    // Chi-square over pairs (2k, 2k+1): compares the observed count of 2k
    // against the pair's average expected count.
    let mut chi = 0.0f64;
    for k in 0..128 {
        let even = hist[2 * k] as f64;
        let odd = hist[2 * k + 1] as f64;
        let expected = (even + odd) / 2.0;
        if expected > 0.0 {
            chi += (even - expected).powi(2) / expected;
        }
    }

    Analysis {
        capacity_bytes: capacity_bytes(rgba.len()),
        lsb_ratio,
        chi_square: chi,
        has_signature: {
            let cap = capacity_bits(rgba.len());
            cap >= MAGIC.len() * 8
                && MAGIC
                    .iter()
                    .enumerate()
                    .all(|(i, m)| read_byte(rgba, i * 8) == *m)
        },
    }
}

/// Produces an RGBA image where each channel's LSB is amplified to black or
/// white — the classic "LSB plane" view. Hidden data shows up as structure
/// or noise in regions that are otherwise flat.
fn lsb_plane_bytes(rgba: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; rgba.len()];
    for (dst, src) in out.chunks_exact_mut(4).zip(rgba.chunks_exact(4)) {
        for c in 0..3 {
            dst[c] = if src[c] & 1 == 1 { 255 } else { 0 };
        }
        dst[3] = 255;
    }
    out
}

// ---------------------------------------------------------------------------
// Wasm-facing API (operates on canvas RGBA buffers)
// ---------------------------------------------------------------------------

/// Encrypts `payload` with `password` and hides it in `rgba` (modified in
/// place and returned). `rgba` is a canvas `ImageData.data` buffer.
#[wasm_bindgen]
pub fn hide(mut rgba: Vec<u8>, payload: &[u8], password: &str) -> Result<Vec<u8>, JsError> {
    let blob = encrypt(password, payload).map_err(|e| JsError::new(&e))?;
    embed(&mut rgba, &blob).map_err(|e| JsError::new(&e))?;
    Ok(rgba)
}

/// Recovers and decrypts a payload hidden by [`hide`].
#[wasm_bindgen]
pub fn reveal(rgba: &[u8], password: &str) -> Result<Vec<u8>, JsError> {
    let blob = extract(rgba).map_err(|e| JsError::new(&e))?;
    decrypt(password, &blob).map_err(|e| JsError::new(&e))
}

/// How many payload bytes fit in an image of this size.
#[wasm_bindgen]
pub fn capacity(rgba_len: usize) -> usize {
    // 28 bytes of overhead: 12-byte nonce + 16-byte GCM tag.
    capacity_bytes(rgba_len).saturating_sub(NONCE_LEN + 16)
}

/// Runs the steganalysis pass.
#[wasm_bindgen]
pub fn analyze(rgba: &[u8]) -> Analysis {
    analyze_bytes(rgba)
}

/// Returns the LSB-plane visualization as an RGBA buffer.
#[wasm_bindgen]
pub fn lsb_plane(rgba: &[u8]) -> Vec<u8> {
    lsb_plane_bytes(rgba)
}

// ---------------------------------------------------------------------------
// Tests (run natively with `cargo test`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_image(pixels: usize) -> Vec<u8> {
        vec![128u8; pixels * 4]
    }

    #[test]
    fn crypto_roundtrip() {
        let blob = encrypt("hunter2", b"attack at dawn").unwrap();
        assert_eq!(decrypt("hunter2", &blob).unwrap(), b"attack at dawn");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let blob = encrypt("hunter2", b"secret").unwrap();
        assert!(decrypt("wrong", &blob).is_err());
    }

    #[test]
    fn embed_extract_roundtrip() {
        let mut img = blank_image(5000);
        let data = b"the quick brown fox jumps over the lazy dog";
        embed(&mut img, data).unwrap();
        assert_eq!(extract(&img).unwrap(), data);
    }

    // Exercises the full hide/reveal path through the pure internals. The
    // #[wasm_bindgen] wrappers (`hide`/`reveal`) can't run off-wasm because
    // JsError aborts, so they're verified by `cargo test` on the wasm target
    // in CI; here we test the identical logic they call.
    fn hide_native(mut rgba: Vec<u8>, payload: &[u8], password: &str) -> Result<Vec<u8>, String> {
        let blob = encrypt(password, payload)?;
        embed(&mut rgba, &blob)?;
        Ok(rgba)
    }
    fn reveal_native(rgba: &[u8], password: &str) -> Result<Vec<u8>, String> {
        decrypt(password, &extract(rgba)?)
    }

    #[test]
    fn full_pipeline() {
        let img = blank_image(10000);
        let hidden = hide_native(img, b"meet at the docks", "p@ss").unwrap();
        assert_eq!(reveal_native(&hidden, "p@ss").unwrap(), b"meet at the docks");
        assert!(reveal_native(&hidden, "nope").is_err());
    }

    #[test]
    fn oversized_payload_errors() {
        let mut img = blank_image(10);
        assert!(embed(&mut img, &vec![0u8; 1000]).is_err());
    }

    #[test]
    fn extract_finds_nothing_in_clean_image() {
        let img = blank_image(1000);
        assert!(extract(&img).is_err());
    }

    #[test]
    fn analysis_flags_our_signature() {
        let img = blank_image(10000);
        let clean = analyze_bytes(&img);
        assert!(!clean.has_signature);

        let hidden = hide_native(blank_image(10000), b"hi", "k").unwrap();
        let dirty = analyze_bytes(&hidden);
        assert!(dirty.has_signature);
        assert!(dirty.capacity_bytes > 0);
    }

    #[test]
    fn lsb_plane_is_binary() {
        let img = blank_image(100);
        let plane = lsb_plane_bytes(&img);
        assert!(plane.chunks_exact(4).all(|p| {
            (p[0] == 0 || p[0] == 255) && p[3] == 255
        }));
    }

    #[test]
    fn capacity_shrinks_with_overhead() {
        // 10000 px * 3 bits = 30000 bits = 3750 bytes raw, minus framing/crypto.
        assert!(capacity(10000 * 4) < 3750);
        assert!(capacity(10000 * 4) > 3600);
    }
}
