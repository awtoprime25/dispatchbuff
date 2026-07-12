// relay/scripts/sync-assets.mjs
// Copies ../../mobile/  →  ./public/  before wrangler dev / wrangler deploy.
// Run automatically via the "predev" and "predeploy" npm scripts.
import { cpSync, mkdirSync, rmSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, '..', '..', 'mobile');
const dest = resolve(here, '..', 'public');

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(src, dest, { recursive: true });

// iOS standalone PWAs cache script/style URLs far more aggressively than a
// normal browser tab and don't reliably re-check them on reopen -- a fixed
// filename (app.js) could keep serving a build from days ago no matter what
// the server sends. Stamp every deploy with a fresh query string so the URL
// itself changes and every caching layer (HTTP, iOS's, a service worker's)
// is forced to treat it as a new resource.
const v = Date.now();
for (const file of readdirSync(dest)) {
  if (!file.endsWith('.html')) continue;
  const p = resolve(dest, file);
  const html = readFileSync(p, 'utf8').replace(
    /(src|href)="(\/(?:app|pair)\.js|\/styles\.css)"/g,
    (_, attr, path) => `${attr}="${path}?v=${v}"`
  );
  writeFileSync(p, html);
}

console.log(`[sync-assets] ${src}  →  ${dest}  (v=${v})`);
