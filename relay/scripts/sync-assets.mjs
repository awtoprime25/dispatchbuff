// relay/scripts/sync-assets.mjs
// Copies ../../mobile/  →  ./public/  before wrangler dev / wrangler deploy.
// Run automatically via the "predev" and "predeploy" npm scripts.
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, '..', '..', 'mobile');
const dest = resolve(here, '..', 'public');

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(src, dest, { recursive: true });
console.log(`[sync-assets] ${src}  →  ${dest}`);
