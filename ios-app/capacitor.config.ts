import type { CapacitorConfig } from '@capacitor/cli';

// This shell never bundles the PWA — it just points a native WKWebView at the
// deployed Cloudflare Worker. UI changes ship via `wrangler deploy` (mobile/),
// no app rebuild needed. Only rebuild ios-app/ if the relay URL changes or
// native config (icon, permissions) needs updating.
const config: CapacitorConfig = {
  appId: 'com.awtoprime.dispatchfreebuff',
  appName: 'DispatchFreeBuff',
  webDir: 'www',
  server: {
    url: 'https://dispatch-relay.awtoprime25.workers.dev',
    cleartext: false,
  },
};

export default config;
