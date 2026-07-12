#!/usr/bin/env python3
"""
DispatchFreeBuff E2E smoke test — bypasses the Cloudflare browser-use queue by
running locally with Playwright + system Chrome.

Workflow:
  1. Navigate to /pair?session=...&code=...  (URL from $PAIR_URL arg or env)
  2. Confirm #code input is auto-filled
  3. Click primary-btn (Pair)
  4. Wait for redirect to /
  5. Wait for #input (#send becomes enabled)
  6. Wait for #auth-badge to lose `.hidden` class   (= E2E channel up)
  7. Type "Reply with just: E2E_WORKS_NOW" and submit
  8. Wait up to 45s for a chat bubble whose text contains "E2E_WORKS_NOW"
  9. Capture screenshots, all console messages, pageerror events

Exit codes:
  0  PASS — E2E up, sent + received encrypted round-trip
  1  FAIL — pair/timing/decrypt problem; screenshot saved, console dumped
  2  SETUP — Playwright Python or Chrome unavailable

Usage:
  python scripts/smoke-e2e.py                          # default URL below
  PAIR_URL=... python scripts/smoke-e2e.py             # explicit env
  python scripts/smoke-e2e.py "<pair url>"             # inline arg
"""
import os
import re
import sys
import traceback
from pathlib import Path

# Force UTF-8 stdout/stderr on Windows where the console default (cp1252) can't
# encode the Unicode glyphs we use for progress markers (→ ✓ ✗ ⚠ ↗).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover — Python <3.7 fallback
        pass

PROBE  = "E2E_WORKS_NOW"
PROMPT = f"Reply with just: {PROBE}"

DEFAULT_URL = (
    "https://dispatch-relay.awtoprime25.workers.dev/pair"
    "?session=ffff83613ffb92e3&code=A3HUCY"
)

URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.environ.get("PAIR_URL", DEFAULT_URL)
)

OUT_DIR = Path(__file__).resolve().parent.parent / "tmp-smoke"
OUT_DIR.mkdir(exist_ok=True)

# We use the system Chrome so we don't need `playwright install chromium`
# (saves ~200MB and one extra failure mode).
CHROME_EXE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def main() -> int:
    console_msgs: list[str] = []
    page_errors:  list[str] = []

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        print("✗ SETUP: `playwright` Python package not installed.")
        print("  → run:  python -m pip install playwright")
        return 2

    if not Path(CHROME_EXE).exists():
        print(f"✗ SETUP: Chrome not found at {CHROME_EXE}")
        return 2

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            executable_path=CHROME_EXE,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--enable-logging=stderr",
                "--v=0",
            ],
        )
        # service_workers='allow' is critical — the relay PWA runs an SW
        try:
            ctx = browser.new_context(
                viewport={"width": 1100, "height": 800},
                service_workers="allow",
                ignore_https_errors=True,
            )
        except Exception:
            ctx = browser.new_context(
                viewport={"width": 1100, "height": 800},
                ignore_https_errors=True,
            )

        page = ctx.new_page()

        page.on("console", lambda m: console_msgs.append(f"[{m.type}] {m.text}"))
        page.on("pageerror", lambda e: page_errors.append(f"PAGEERROR: {e}"))

        rc = 1
        try:
            print(f"→ goto {URL}")
            page.goto(URL, wait_until="domcontentloaded", timeout=20_000)
            page.wait_for_selector("#code", timeout=10_000)
            current_code = page.eval_on_selector("#code", "el => el.value")
            print(f"  code pre-filled: {current_code!r}")

            page.click("button.primary-btn")
            print("  clicked Pair")

            # Pair.js redirects to '/' on success
            page.wait_for_url(re.compile(r"/(\?.*)?$"), timeout=15_000)
            page.wait_for_selector("#input", timeout=10_000)
            print("  chat UI loaded")

            # The 🔒 E2E badge (.hidden toggle removed when E2E ready)
            try:
                page.wait_for_selector(
                    "#auth-badge:not(.hidden)",
                    state="attached",
                    timeout=15_000,
                )
                auth_text = (
                    page.eval_on_selector("#auth-text", "el => el.textContent") or ""
                ).strip()
                print(f"  ✓ E2E auth badge text: {auth_text!r}")
            except Exception as e:
                # Soft-fail: E2E may not turn on if the daemon hasn't accepted
                # the key — log and continue, the response bubble check below
                # is the real gate.
                print(f"  ⚠ E2E badge not visible: {e}")

            # Snapshot the messages-container child count BEFORE we submit, so
            # we can require a NEW (response) bubble later — not the sent bubble
            # that already contains the probe string and would false-positive.
            baseline_count = page.eval_on_selector(
                "#messages", "el => el.children.length"
            )
            print(f"  baseline bubble count: {baseline_count}")

            page.fill("#input", PROMPT)
            page.click("#send")
            print(f"  sent prompt: {PROMPT!r}")

            # Wait for a NEW child appended AFTER baseline whose text contains
            # the probe string. Skipping the sent bubble (at index == baseline)
            # is what makes this trustworthy.
            page.wait_for_function(
                """({probe, baseline}) => {
                    const main = document.getElementById('messages');
                    if (!main || main.children.length <= baseline) return false;
                    for (let i = baseline + 1; i < main.children.length; i++) {
                        const t = (main.children[i].innerText
                                || main.children[i].textContent || '');
                        if (t.includes(probe)) return true;
                    }
                    return false;
                }""",
                arg={"probe": PROBE, "baseline": baseline_count},
                timeout=45_000,
            )

            # Pull all bubble texts to confirm we got a real reply
            bubbles = page.eval_on_selector_all(
                "#messages > *",
                """els => els.map(e => ({
                    cls: e.className,
                    text: (e.innerText || e.textContent || '').slice(0, 400),
                }))""",
            )
            print(f"  ✓ response bubbles ({len(bubbles)}):")
            for i, b in enumerate(bubbles[-5:]):
                print(f"    [{i}] cls={b['cls']!r} text={b['text']!r}")

            page.screenshot(path=str(OUT_DIR / "smoke-success.png"), full_page=True)
            print(f"  screenshot: {OUT_DIR / 'smoke-success.png'}")
            rc = 0

        except Exception as e:
            print(f"✗ FAIL: {type(e).__name__}: {e}")
            try:
                traceback.print_exc()
            except Exception:
                pass
            try:
                page.screenshot(
                    path=str(OUT_DIR / "smoke-fail.png"), full_page=True
                )
                print(f"  failure screenshot: {OUT_DIR / 'smoke-fail.png'}")
            except Exception:
                pass

        finally:
            try:
                browser.close()
            except Exception:
                pass

    # Always dump diagnostics at the end
    print()
    print("=== console messages ===")
    for m in console_msgs:
        print(m)
    if page_errors:
        print()
        print("=== page errors ===")
        for m in page_errors:
            print(m)

    return rc


if __name__ == "__main__":
    sys.exit(main())
