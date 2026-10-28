import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

function loadForm(filename, invoke) {
  const elements = new Map();
  function element(selector) {
    if (!elements.has(selector)) elements.set(selector, {
      value: '', textContent: '', disabled: false, handlers: {},
      addEventListener(name, fn) { this.handlers[name] = fn; },
      querySelector: element,
    });
    return elements.get(selector);
  }
  const timers = [];
  const redirects = [];
  let now = 0;
  const context = vm.createContext({
    document: { querySelector: element },
    window: { __TAURI__: { core: { invoke } }, location: { replace: (url) => redirects.push(url) } },
    console: { error() {} },
    setTimeout(fn) { timers.push(fn); },
    Date: { now: () => now },
  });
  vm.runInContext(readFileSync(new URL(`../src/${filename}`, import.meta.url), 'utf8'), context);
  return { element, timers, redirects, advance() { now += 100000; } };
}

test('create prevents concurrent submissions and clears submitted fields', async () => {
  let finish;
  let calls = 0;
  const ui = loadForm('create.js', () => { calls++; return new Promise(resolve => { finish = resolve; }); });
  ui.element('#masterPassword').value = 'synthetic-password';
  ui.element('#confirmPassword').value = 'synthetic-password';
  const submit = ui.element('#passwordForm').handlers.submit;
  const first = submit({ preventDefault() {} });
  await submit({ preventDefault() {} });
  assert.equal(calls, 1);
  assert.equal(ui.element('#masterPassword').value, '');
  assert.equal(ui.element('#confirmPassword').value, '');
  finish();
  await first;
  assert.deepEqual(ui.redirects, ['index.html']);
});

test('unlock prevents concurrent submissions and clears password field', async () => {
  let finish;
  let calls = 0;
  const ui = loadForm('unlock.js', () => { calls++; return new Promise(resolve => { finish = resolve; }); });
  ui.element('#password').value = 'synthetic-password';
  const submit = ui.element('#unlock-form').handlers.submit;
  const first = submit({ preventDefault() {} });
  await submit({ preventDefault() {} });
  assert.equal(calls, 1);
  assert.equal(ui.element('#password').value, '');
  finish();
  await first;
  assert.deepEqual(ui.redirects, ['index.html']);
});

test('retry timers and Enter cannot bypass the five-failure UI lockout', async () => {
  let calls = 0;
  const ui = loadForm('unlock.js', async () => { calls++; throw new Error('Wrong password'); });
  const submit = ui.element('#unlock-form').handlers.submit;
  for (let i = 0; i < 5; i++) {
    ui.element('#password').value = 'synthetic-password';
    await submit({ preventDefault() {} });
    ui.advance();
    ui.timers.splice(0).forEach(fn => fn());
  }
  assert.equal(ui.element('#unlock-btn').disabled, true);
  await submit({ preventDefault() {} });
  assert.equal(calls, 5);
});
