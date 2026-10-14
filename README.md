# Steganography Studio

An educational **steganography + steganalysis** tool written in Rust, compiled to WebAssembly, and deployed to GitHub Pages. Everything runs in the browser — no image or password ever leaves the user's device.

Built as a teaching demo for a cybersecurity club: it's meant to *show* how LSB hiding works, why encryption matters on top of it, and how detectable the result is.

## What it does

- **Hide** — embed a text message or any file inside a cover image. The payload is first encrypted with **AES-256-GCM** (key derived from a password via SHA-256), then written into the least-significant bits of the image's RGB channels. Output is a lossless PNG.
- **Reveal** — recover and decrypt the payload with the password. A wrong password fails the GCM authentication tag, so you get a clear error instead of garbage.
- **Analyze** — basic steganalysis: payload capacity, LSB-set ratio, a chi-square statistic over adjacent value pairs, detection of this tool's own signature, and a visual **LSB-plane** view where hidden data shows up as structure in otherwise-noisy bits.

## The lesson it's built to teach

- LSB steganography is **fragile**: re-saving the image as JPEG, resizing, or recompressing destroys the hidden bits. Always keep and share the PNG.
- It is **detectable** — the Analyze tab demonstrates exactly how.
- Hiding is **not** confidentiality. The AES layer is what actually protects the content if someone suspects data is present.

## Project layout

```
src/lib.rs                     Rust: AES-GCM crypto, LSB embed/extract, steganalysis
www/index.html                 Three-tab UI (Hide / Reveal / Analyze) calling into Rust
build.sh                       Compiles Rust → .wasm, generates JS glue, assembles ./dist
.github/workflows/deploy.yml   CI: test, build, publish ./dist to GitHub Pages
```

## Publish it

1. Push this folder to a new GitHub repo's `main` branch:
   ```bash
   git init && git add . && git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/Perceus64/steg-studio.git
   git push -u origin main
   ```
2. In the repo: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
3. Watch the **Actions** tab. The site lands at `https://perceus64.github.io/steg-studio/`.

If the first run fails at the deploy step because Pages wasn't enabled yet, do step 2 and **Re-run jobs**.

## Run locally

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100 --locked
bash build.sh
python3 -m http.server -d dist 8080   # open http://localhost:8080
```

Run the Rust unit tests with `cargo test` (crypto roundtrip, embed/extract, wrong-password rejection, capacity limits, analysis).

## Notes

- Key derivation is a single SHA-256 of the password — fine for a classroom demo, but a real tool would use a slow KDF like Argon2id. Swapping it in is a good follow-up exercise.
- To extend: add a new `#[wasm_bindgen]` function in `src/lib.rs`, rebuild, and call it from the `<script>` in `www/index.html`.
