// Self-check: mirrors the mode-detection + screen-render logic added to
// daemon/src/index.ts's attachTerm(), without spinning up a real pty.
import xtermHeadless from '@xterm/headless';
import assert from 'node:assert';
const { Terminal: HeadlessTerminal } = xtermHeadless;

const term = new HeadlessTerminal({ cols: 20, rows: 5, allowProposedApi: true });

function renderScreen() {
  const buf = term.buffer.active;
  const lines = [];
  for (let i = 0; i < term.rows; i++) lines.push(buf.getLine(i)?.translateToString(true) ?? '');
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.join('\n');
}

function writeSync(data) {
  return new Promise(resolve => term.write(data, resolve));
}

const results = [];
await writeSync('hello\r\n');
results.push(['normal buffer before alt-screen', term.buffer.active.type, 'normal']);

// Enter alternate screen buffer (smcup) + draw a fake TUI frame.
await writeSync('\x1b[?1049h\x1b[H\x1b[2Jmenu line 1\r\nmenu line 2');
results.push(['alternate buffer active', term.buffer.active.type, 'alternate']);
results.push(['screen render captures TUI frame', renderScreen(), 'menu line 1\nmenu line 2']);

// Redraw the TUI frame (simulates an Ink re-render).
await writeSync('\x1b[H\x1b[2Jmenu line 1 v2\r\nmenu line 2 v2');
results.push(['screen render reflects redraw', renderScreen(), 'menu line 1 v2\nmenu line 2 v2']);

// Exit alternate screen (rmcup) — back to normal/line mode.
await writeSync('\x1b[?1049l');
results.push(['back to normal buffer after TUI exit', term.buffer.active.type, 'normal']);

let failed = false;
for (const [label, actual, expected] of results) {
  const ok = actual === expected;
  if (!ok) failed = true;
  console.log(`${ok ? 'PASS' : 'FAIL'} — ${label}: ${JSON.stringify(actual)} ${ok ? '==' : '!='} ${JSON.stringify(expected)}`);
}
assert.ok(!failed, 'one or more assertions failed');
console.log('\nAll checks passed.');
