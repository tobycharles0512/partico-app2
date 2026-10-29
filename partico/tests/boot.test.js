// Headless boot smoke test for partico/Partico-updated.html.
//
// Boots the real app in jsdom (local React 18.2.0 UMD builds instead of the CDN,
// fetch stubbed with fixtures from boot.fixtures.js, logged-in localStorage),
// then visits every main screen and fails on any uncaught error, unhandled
// rejection, or console.error (which includes the app's ErrorBoundary). It only
// asserts on fixture *data* (titles, names), never on markup, so redesigns of a
// screen shouldn't break it unless the data stops rendering.
//
// Run (one-time install first):
//   cd partico/tests && npm install
//   node --test partico/tests/*.test.js        # from the repo root
// Without node_modules this test is skipped, not failed.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { readHtml } = require('./helpers');
const fx = require('./boot.fixtures');

const NM = path.join(__dirname, 'node_modules');
const HAVE_DEPS = ['jsdom', 'react/umd/react.production.min.js', 'react-dom/umd/react-dom.production.min.js']
  .every((p) => fs.existsSync(path.join(NM, p)));
const SKIP = HAVE_DEPS ? false : 'jsdom/react not installed — run: cd partico/tests && npm install';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const inlineScript = (src) => '<script>' + src.replace(/<\/script/gi, '<\\/script') + '</script>';

// Swap the CDN React/ReactDOM tags for the local UMD builds. Other external
// resources (leaflet/maplibre loader, stylesheets, fonts) are never fetched
// because jsdom isn't given `resources: "usable"`.
function buildHtml() {
  let html = readHtml();
  const react = fs.readFileSync(path.join(NM, 'react/umd/react.production.min.js'), 'utf8');
  const reactDom = fs.readFileSync(path.join(NM, 'react-dom/umd/react-dom.production.min.js'), 'utf8');
  const reactTag = /<script[^>]*src="[^"]*\/react\/18\.2\.0\/umd\/react\.production\.min\.js"[^>]*><\/script>/;
  const domTag = /<script[^>]*src="[^"]*\/react-dom\/18\.2\.0\/umd\/react-dom\.production\.min\.js"[^>]*><\/script>/;
  assert.match(html, reactTag, 'React CDN <script> tag not found — update boot.test.js');
  assert.match(html, domTag, 'ReactDOM CDN <script> tag not found — update boot.test.js');
  html = html.replace(reactTag, () => inlineScript(react)).replace(domTag, () => inlineScript(reactDom));
  return html;
}

// A 2D context where every method is a no-op; enough for the fireworks canvas
// and the cover-luminance probe.
function fakeContext2d(canvas) {
  const gradient = { addColorStop() {} };
  const known = {
    canvas,
    createLinearGradient: () => gradient,
    createRadialGradient: () => gradient,
    createPattern: () => null,
    measureText: (t) => ({ width: String(t || '').length * 6 }),
    getImageData: (x, y, w, h) => ({ width: w, height: h, data: new Uint8ClampedArray(Math.max(1, w * h * 4)) }),
    createImageData: (w, h) => ({ width: w, height: h, data: new Uint8ClampedArray(Math.max(1, w * h * 4)) }),
    getLineDash: () => [],
    isPointInPath: () => false,
  };
  const store = {};
  return new Proxy(store, {
    get: (t, k) => (k in known ? known[k] : k in t ? t[k] : () => {}),
    set: (t, k, v) => { t[k] = v; return true; },
  });
}

// Chainable Leaflet stand-in: any property is a function returning the stub.
function chainStub() {
  const fn = function () { return proxy; };
  const proxy = new Proxy(fn, {
    get: (t, k) => {
      if (k === Symbol.toPrimitive) return () => 0;
      if (k === 'then') return undefined; // not a thenable
      if (k === 'maplibreGL') return undefined; // use the raster fallback path
      return proxy;
    },
    apply: () => proxy,
    construct: () => proxy,
  });
  return proxy;
}

function jsonResponse(status, body) {
  const text = JSON.stringify(body);
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: () => Promise.resolve(JSON.parse(text)),
    text: () => Promise.resolve(text),
  });
}

// Fake backend. Records every request; unknown routes are listed in `unhandled`.
function makeFetch(log) {
  return (input, opts = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const method = (opts.method || 'GET').toUpperCase();
    const p = url.pathname;
    log.calls.push(method + ' ' + p);
    const auth = (opts.headers && (opts.headers.Authorization || opts.headers.authorization)) || '';
    if (p.startsWith('/api/') && !p.startsWith('/api/auth/') && auth !== 'Bearer ' + fx.AUTH_TOKEN) {
      return jsonResponse(401, { error: 'No token provided' });
    }
    if (method === 'GET' && p === '/api/state') return jsonResponse(200, fx.stateResponse());
    if (method === 'GET' && p === '/api/discover') return jsonResponse(200, fx.discoverResponse());
    if (method === 'GET' && p === '/api/users/search') return jsonResponse(200, fx.searchResponse(url.searchParams.get('q')));
    if (method === 'GET' && p === '/api/auth/me') return jsonResponse(200, { user: fx.rows.u_me });
    if (method !== 'GET' && p.startsWith('/api/')) return jsonResponse(200, { success: true });
    log.unhandled.push(method + ' ' + url.href);
    return jsonResponse(404, { error: 'Not found' });
  };
}

async function bootApp() {
  const { JSDOM, VirtualConsole } = require('jsdom');
  const errors = [];
  const log = { calls: [], unhandled: [] };
  const fmt = (args) => args.map((a) => (a && a.stack) || (typeof a === 'object' ? safeJson(a) : String(a))).join(' ');
  const vc = new VirtualConsole();
  vc.on('error', (...args) => errors.push('console.error: ' + fmt(args)));
  vc.on('jsdomError', (e) => errors.push('jsdom: ' + ((e.detail && e.detail.stack) || e.stack || e.message)));

  const onRejection = (r) => errors.push('unhandledRejection: ' + ((r && r.stack) || r));
  process.on('unhandledRejection', onRejection);

  const dom = new JSDOM(buildHtml(), {
    url: 'https://partico.app/',
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(window) {
      const seed = fx.seedLocalStorage();
      for (const k of Object.keys(seed)) window.localStorage.setItem(k, seed[k]);
      window.fetch = makeFetch(log);
      window.addEventListener('error', (ev) => errors.push('window error: ' + ((ev.error && ev.error.stack) || ev.message)));
      window.addEventListener('unhandledrejection', (ev) => errors.push('unhandledrejection: ' + ((ev.reason && ev.reason.stack) || ev.reason)));
      class IO { constructor(cb) { this.cb = cb; } observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } }
      window.IntersectionObserver = IO;
      window.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
      window.matchMedia = (q) => ({ matches: false, media: q, onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return false; } });
      window.scrollTo = () => {};
      window.scrollBy = () => {};
      window.Element.prototype.scrollIntoView = function () {};
      window.Element.prototype.scrollTo = function () {};
      if (!window.Element.prototype.animate) {
        window.Element.prototype.animate = function () {
          return { finished: Promise.resolve(), cancel() {}, finish() {}, play() {}, pause() {}, reverse() {}, addEventListener() {}, removeEventListener() {}, onfinish: null };
        };
      }
      window.HTMLCanvasElement.prototype.getContext = function (type) { return type === '2d' ? fakeContext2d(this) : null; };
      window.HTMLCanvasElement.prototype.toDataURL = () => 'data:image/png;base64,';
      window.HTMLMediaElement.prototype.play = () => Promise.resolve();
      window.HTMLMediaElement.prototype.pause = () => {};
      window.L = chainStub();
      window.maplibregl = chainStub();
      Object.defineProperty(window.navigator, 'clipboard', { value: { writeText: () => Promise.resolve() }, configurable: true });
      Object.defineProperty(window.navigator, 'geolocation', { value: { getCurrentPosition() {}, watchPosition() { return 0; }, clearWatch() {} }, configurable: true });
    },
  });
  const { window } = dom;

  // Rendered text only (no <script>/<style> source, which would match anything).
  const text = () => {
    const doc = window.document;
    const walker = doc.createTreeWalker(doc.body, window.NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => (n.parentElement && n.parentElement.closest('script,style,noscript') ? window.NodeFilter.FILTER_REJECT : window.NodeFilter.FILTER_ACCEPT),
    });
    let out = '';
    while (walker.nextNode()) out += walker.currentNode.nodeValue + ' ';
    return out.replace(/\s+/g, ' ');
  };
  // Click the first button whose visible text matches `re` (labels, not markup).
  async function clickButton(re) {
    const btn = [...window.document.querySelectorAll('button,[role="button"]')].find((b) => re.test((b.textContent || '').trim()));
    assert.ok(btn, 'no button matching ' + re + '. Page text:\n' + text().slice(0, 1500));
    btn.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
    await sleep(60);
  }
  // Type into an <input> the way React notices (native value setter + input event).
  async function typeInto(input, value) {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, value);
    input.dispatchEvent(new window.Event('input', { bubbles: true }));
    await sleep(60);
  }
  async function waitForText(needle, ms = 4000) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (text().includes(needle)) return true;
      await sleep(25);
    }
    return false;
  }
  // The AppProvider context value (navigate, getParty, ...), found by walking
  // React's fiber tree from #root. Test-only; needs no hook in the app.
  function appContext() {
    const rootEl = window.document.getElementById('root');
    const key = Object.keys(rootEl).find((k) => k.startsWith('__reactContainer$'));
    assert.ok(key, 'React root not mounted on #root');
    // The container points at the HostRoot fiber; its FiberRoot knows which tree is current.
    const stack = [rootEl[key].stateNode.current];
    while (stack.length) {
      const f = stack.pop();
      if (!f) continue;
      const v = f.memoizedProps && f.memoizedProps.value;
      if (f.type && f.type._context && v && typeof v.navigate === 'function') return v;
      if (f.sibling) stack.push(f.sibling);
      if (f.child) stack.push(f.child);
    }
    throw new Error('AppProvider context (with navigate) not found in the React tree');
  }
  async function go(screen, data) {
    appContext().navigate(screen, data || {});
    await sleep(60);
  }
  function close() {
    process.removeListener('unhandledRejection', onRejection);
    window.close();
  }
  return { dom, window, errors, log, text, waitForText, appContext, go, clickButton, typeInto, close };
}

function safeJson(o) {
  try { return JSON.stringify(o); } catch { return String(o); }
}

test('app boots logged in and every main screen renders fixture data without errors', { skip: SKIP, timeout: 60000 }, async (t) => {
  const app = await bootApp();
  const { TITLES } = fx;
  const noErrors = (where) => assert.deepStrictEqual(app.errors, [], 'runtime errors ' + where + ':\n' + app.errors.join('\n\n'));
  try {
    // Splash runs ~2.2s, then a logged-in user lands on home.
    assert.ok(await app.waitForText(TITLES.attending, 6000), 'home never showed the next party ("' + TITLES.attending + '"). Errors:\n' + app.errors.join('\n\n') + '\nPage text:\n' + app.text().slice(0, 1500));
    assert.ok(app.log.calls.includes('GET /api/state'), 'app did not call GET /api/state');
    const ctx = app.appContext();
    assert.strictEqual(ctx.screen, 'home');
    assert.strictEqual(ctx.currentUser && ctx.currentUser.id, fx.ME, 'not logged in as the fixture user');
    noErrors('booting to home');

    const screens = [
      ['home', {}, [TITLES.attending, TITLES.hosted]],
      ['invitation', { partyId: 'p_invited' }, [TITLES.invited]],
      ['partyDetail', { partyId: 'p_past_attended' }, [TITLES.pastAttended]],
      ['partyDetail', { partyId: 'p_past_attended', tab: 'photos' }, [TITLES.pastAttended]],
      ['partyDetail', { partyId: 'p_attending' }, [TITLES.attending]],
      ['partyManage', { partyId: 'p_hosted' }, [TITLES.hosted]],
      ['partyManage', { partyId: 'p_past_hosted' }, [TITLES.pastHosted]],
      ['friends', {}, ['Ava Thompson', 'Finn Walsh']],
      ['profile', {}, ['Toby']],
      ['notifications', {}, [TITLES.invited]],
      ['calendar', {}, [TITLES.attending]],
      ['discover', {}, [TITLES.discover]],
      ['messageThread', { partyId: 'p_attending', guestId: fx.ME }, ['Can you bring candles?']],
      ['createParty', {}, []],
    ];
    for (const [screen, data, needles] of screens) {
      await t.test(screen + (data.partyId ? ' (' + data.partyId + (data.tab ? ', ' + data.tab + ' tab' : '') + ')' : ''), async () => {
        await app.go(screen, data);
        assert.strictEqual(app.appContext().screen, screen);
        for (const n of needles) {
          assert.ok(await app.waitForText(n, 6000), screen + ' did not show "' + n + '". Page text:\n' + app.text().slice(0, 1500));
        }
        await sleep(150); // let effects/timers settle
        noErrors('on ' + screen);
      });
    }
    await t.test('partyManage: guests tab lists every RSVP and the unapproved +1', async () => {
      await app.go('partyManage', { partyId: 'p_hosted' });
      await app.clickButton(/Guests/);
      for (const n of ['Ava Thompson', 'Ella Rossi', 'Chloe Martin', 'Dev Patel', 'Sam Rivers']) {
        assert.ok(await app.waitForText(n), 'guests tab did not show "' + n + '". Page text:\n' + app.text().slice(0, 1500));
      }
      noErrors('on partyManage guests tab');
    });
    // Known gap: PartyManageScreen groups guests by ["accepted","pending","declined"]
    // only, so a "maybe" RSVP (offered on the invitation screen) never appears.
    await t.test('partyManage: guests tab shows the "maybe" guest', { todo: 'app bug: maybe RSVPs are not listed on the host guest tab' }, async () => {
      assert.ok(await app.waitForText('Ben Okafor', 300), 'maybe guest Ben Okafor not listed');
    });
    await t.test('partyManage: photos tab of a past party renders', async () => {
      await app.go('partyManage', { partyId: 'p_past_hosted' });
      await app.clickButton(/Photos/);
      assert.strictEqual(app.window.document.querySelectorAll('img[src^="data:image/png"]').length >= 2, true, 'expected the 2 fixture photos as <img>');
      noErrors('on partyManage photos tab');
    });
    await t.test('friends: requests tab shows the incoming request; find-people search hits /api/users/search', async () => {
      await app.go('friends');
      await app.clickButton(/^Requests/);
      assert.ok(await app.waitForText('Grace Lin'), 'incoming friend request from Grace Lin not shown');
      await app.clickButton(/^Find People/);
      const input = app.window.document.querySelector('input:not([type]),input[type="text"],input[type="search"]');
      assert.ok(input, 'no search input on the Find People tab');
      await app.typeInto(input, 'hana');
      assert.ok(await app.waitForText('Hana Kim'), 'search result for "hana" not shown');
      assert.ok(app.log.calls.includes('GET /api/users/search'), 'search did not call the backend');
      noErrors('on friends tabs');
    });
    assert.deepStrictEqual(app.log.unhandled, [], 'app called endpoints the fixture backend does not know about');
  } finally {
    app.close();
  }
});
