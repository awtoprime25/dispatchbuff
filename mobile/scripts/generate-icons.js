// mobile/scripts/generate-icons.js
// Rasterize mobile/icon.svg into all iOS + Android + PWA icon variants.
// Also produces 12 iPhone splash screens (apple-touch-startup-image).
//
// Usage:  node mobile/scripts/generate-icons.js
// Reads:  mobile/icon.svg
// Writes: mobile/icons/icon-{N}.png  (N in {16,32,60,76,96,120,152,167,180,192,512})
//         mobile/icons/apple-touch-startup-image-{WxH}.png
//
// iOS uses background-only startup images; the icon should be centered with
// Apple safe-area insets respected on notched devices (X+).

const fs   = require('node:fs');
const path = require('node:path');
const sharp = require('sharp');

const ROOT  = path.resolve(__dirname, '..');
const SVG_PATH = path.join(ROOT, 'icon.svg');
const OUT_DIR  = path.join(ROOT, 'icons');
fs.mkdirSync(OUT_DIR, { recursive: true });

const ICON_SIZES = [16, 32, 60, 76, 96, 120, 152, 167, 180, 192, 256, 512];

// Splash sizes — (device-width, device-height) at native scale, portrait only.
// Source: Apple "Human Interface Guidelines" + developer.apple.com sample.
// We pad with safe-area-inset so the centered icon doesn't clip behind the notch.
const SPLASH = [
  // (label, width, height, safeTop, safeBottom, safeLeft, safeRight)
  { name: '640x1136',     w:  640, h: 1136, top:    0, bot:    0, left:   0, right:   0 }, // iPhone 5/SE
  { name: '750x1334',     w:  750, h: 1334, top:    0, bot:    0, left:   0, right:   0 }, // iPhone 6/7/8/SE2/SE3
  { name: '1242x2208',    w: 1242, h: 2208, top:    0, bot:    0, left:   0, right:   0 }, // iPhone 6+/7+/8+
  { name: '828x1792',     w:  828, h: 1792, top:  44, bot:   34, left:   0, right:   0 }, // iPhone XR/11
  { name: '1125x2436',    w: 1125, h: 2436, top:  44, bot:   34, left:   0, right:   0 }, // iPhone X/XS/11 Pro
  { name: '1242x2688',    w: 1242, h: 2688, top:  44, bot:   34, left:   0, right:   0 }, // iPhone XS Max/11 Pro Max
  { name: '1080x2340',    w: 1080, h: 2340, top:  44, bot:   28, left:   0, right:   0 }, // iPhone 12 mini / 13 mini
  { name: '1170x2532',    w: 1170, h: 2532, top:  47, bot:   34, left:   0, right:   0 }, // iPhone 12/12 Pro/13/13 Pro/14
  { name: '1284x2778',    w: 1284, h: 2778, top:  47, bot:   34, left:   0, right:   0 }, // iPhone 12/13/14 Plus/Pro Max
  { name: '1179x2556',    w: 1179, h: 2556, top:  47, bot:   34, left:   0, right:   0 }, // iPhone 14 Pro/15/15 Pro/16
  { name: '1290x2796',    w: 1290, h: 2796, top:  47, bot:   34, left:   0, right:   0 }, // iPhone 14 Pro Max/15 Plus/15 Pro Max/16 Plus
  { name: '1320x2868',    w: 1320, h: 2868, top:  59, bot:   49, left:   0, right:   0 }, // iPhone 16 Pro Max
];

const svg = fs.readFileSync(SVG_PATH);

async function renderIcons() {
  const promises = ICON_SIZES.map((size) =>
    sharp(svg, { density: 384 })
      .resize(size, size, { fit: 'contain', background: '#00000000' })
      .png({ compressionLevel: 9 })
      .toFile(path.join(OUT_DIR, `icon-${size}.png`))
      .then(() => console.log(`✓ icons/icon-${size}.png`))
  );
  await Promise.all(promises);
}

async function renderSplashes() {
  // Master 512px icon — sharper downsampling results in cleaner centered renders.
  const masterIcon = await sharp(svg, { density: 384 })
    .resize(512, 512, { fit: 'contain', background: '#00000000' })
    .png()
    .toBuffer();

  const promises = SPLASH.map(async (s) => {
    const usableW = s.w - s.left - s.right;
    const usableH = s.h - s.top  - s.bot;
    const iconFit = Math.min(usableW, usableH) * 0.42;       // 42% of shortest usable axis
    const centered = await sharp(masterIcon)
      .resize(Math.round(iconFit), Math.round(iconFit), { fit: 'contain' })
      .png()
      .toBuffer();

    const bg = sharp({
      create: { width: s.w, height: s.h, channels: 4, background: { r: 0, g: 0, b: 0, alpha: 1 } },
    });

    await bg
      .composite([{
        input: centered,
        gravity: 'center',
      }])
      .png({ compressionLevel: 9 })
      .toFile(path.join(OUT_DIR, `apple-touch-startup-image-${s.name}.png`));

    console.log(`✓ icons/apple-touch-startup-image-${s.name}.png`);
  });
  await Promise.all(promises);
}

(async () => {
  console.log('→ rendering icons');
  await renderIcons();
  console.log('→ rendering splash screens');
  await renderSplashes();
  console.log('done.');
})().catch((err) => { console.error(err); process.exit(1); });
