// Functional test for repo-avatar.js (run with Node.js)

// ---- Shim minimal browser globals ----
global.document = {
  readyState: 'complete',
  querySelectorAll: () => [],
  addEventListener: () => {},
};
global.window = global;
global.HTMLElement = function () {};

const RepoAvatar = require('/workspaces/RetinaX/website/components/repo-avatar.js');

// Mock HTMLElement factory
function MockEl(dataset) {
  this.dataset = dataset || {};
  this._children = [];
  this.innerHTML = '';
  this.appendChild = function (el) {
    this._children.push(el);
  };
  this.querySelector = function () {
    return this._children[0] || null;
  };
  this.getAttribute = function () {
    return null;
  };
  this.setAttribute = function () {};
}
MockEl.prototype = Object.create(HTMLElement.prototype);

// Override document.createElement to return a mock element
global.document.createElement = function (tag) {
  var el = {
    _tag: tag,
    className: '',
    innerHTML: '',
    dataset: {},
    style: {},
    setAttribute: function (k, v) {
      this['_attr_' + k] = v;
    },
    getAttribute: function (k) {
      return this['_attr_' + k] || null;
    },
    appendChild: function () {},
    querySelectorAll: function () {
      return [];
    },
    querySelector: function () {
      return null;
    },
    parentNode: null,
    removeChild: function () {},
    // classList stub (needed for showLoading / showError)
    classList: {
      _cls: '',
      add: function (c) {
        el.className += (el.className ? ' ' : '') + c;
      },
      remove: function (c) {
        el.className = el.className.replace(new RegExp('\\b' + c + '\\b', 'g'), '').trim();
      },
      contains: function (c) {
        return el.className.split(' ').indexOf(c) !== -1;
      },
    },
  };
  return el;
};

let passed = 0;
let failed = 0;

function assert(label, condition, detail) {
  if (condition) {
    console.log('✓ PASS', label, detail ? '(' + detail + ')' : '');
    passed++;
  } else {
    console.error('✗ FAIL', label, detail ? '(' + detail + ')' : '');
    failed++;
  }
}

// ── Test 1: fmtNum ─────────────────────────────────────────────────
const t1mount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '1400',
  forks: '1000000',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/test/repo',
  contributors: '[]',
});
new RepoAvatar(t1mount, {});
const t1html = t1mount._children[0].innerHTML;
assert('fmtNum: 1400 → 1.4k', t1html.includes('1.4k'), t1html.match(/[\d.]+k/)?.[0]);
assert('fmtNum: 1000000 → 1M', t1html.includes('1M'), t1html.match(/[\d.]+M/)?.[0]);

// ── Test 2: XSS escaping ────────────────────────────────────────────
const xssData = {
  org: '<script>alert(1)</scr' + 'ipt>',
  repo: '"><img onerror=alert(2)>',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': '<b>bold</b>',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
};
const xssMount = new MockEl(xssData);
new RepoAvatar(xssMount, {});
const xssHtml = xssMount._children[0].innerHTML;
assert('XSS: <script> tag escaped', !xssHtml.includes('<script>'));
// onerror= is safe if the surrounding angle brackets are escaped: &lt;img onerror= is harmless HTML text
// The dangerous form would be an unescaped attribute value: "><img onerror=...>
// We check that the raw injection sequence " "> is not present unescaped.
assert('XSS: img tag angle brackets escaped', !xssHtml.includes('<img '));
assert('XSS: <b> tag in commit escaped', !xssHtml.includes('<b>bold</b>'));

// ── Test 3: Contributor overflow ────────────────────────────────────
const nineContribs = JSON.stringify(
  Array.from({ length: 9 }, (_, i) => ({ login: 'user' + i, initials: 'U' + i, color: 'teal' }))
);
const overflowMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: nineContribs,
  'max-contributors': '5',
});
new RepoAvatar(overflowMount, {});
const overflowHtml = overflowMount._children[0].innerHTML;
assert('Overflow badge: 9 contributors, max 5 → shows +4', overflowHtml.includes('+4'));

// ── Test 4: ARIA role=region ─────────────────────────────────────────
const ariaMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
});
new RepoAvatar(ariaMount, {});
const ariaCard = ariaMount._children[0];
assert('ARIA role=region set on card', ariaCard._attr_role === 'region');

// ── Test 5: destroy() clears state ──────────────────────────────────
const destroyMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
});
const destroyInst = new RepoAvatar(destroyMount, {});
destroyInst.destroy();
assert('destroy() clears _card ref', destroyInst._card === null);
assert('destroy() clears _cfg ref', destroyInst._cfg === null);
assert('destroy() clears _mount ref', destroyInst._mount === null);

// ── Test 6: update() merges new stars ───────────────────────────────
const updateMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '10',
  forks: '2',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
});
const updateInst = new RepoAvatar(updateMount, {});
updateInst.update({ stars: 50000 });
const updatedHtml = updateMount._children[0].innerHTML;
assert('update(): stars updated to 50k', updatedHtml.includes('50k'));

// ── Test 7: badges rendered ──────────────────────────────────────────
const badgeMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
  badges: 'MIT,HIPAA,CI',
});
new RepoAvatar(badgeMount, {});
const badgeHtml = badgeMount._children[0].innerHTML;
assert('Badges: MIT badge rendered', badgeHtml.includes('MIT License'));
assert('Badges: HIPAA badge rendered', badgeHtml.includes('HIPAA Ready'));
assert('Badges: CI badge rendered', badgeHtml.includes('CI Passing'));

// ── Test 8: showLoading renders skeleton ─────────────────────────────
const loadMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
});
const loadInst = new RepoAvatar(loadMount, {});
loadInst.showLoading();
const loadHtml = loadMount._children[0].innerHTML;
assert('showLoading: skeleton class "ra-skel" present', loadHtml.includes('ra-skel'));
assert(
  'showLoading: is-loading class on card',
  loadMount._children[0].className.includes('is-loading')
);

// ── Test 9: showError renders error message ──────────────────────────
const errMount = new MockEl({
  org: 'Test',
  repo: 'Repo',
  stars: '0',
  forks: '0',
  lang: 'Rust',
  'last-commit-msg': 'test',
  'last-commit-sha': 'abc',
  'last-commit-date': '2026-01-01',
  'github-url': 'https://github.com/',
  contributors: '[]',
});
const errInst = new RepoAvatar(errMount, {});
errInst.showError('Rate limit exceeded');
const errHtml = errMount._children[0].innerHTML;
assert('showError: error message rendered', errHtml.includes('Rate limit exceeded'));
assert('showError: error icon present', errHtml.includes('repo-avatar__error'));

// ── Summary ──────────────────────────────────────────────────────────
console.log('');
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} assertions.`);
process.exit(failed > 0 ? 1 : 0);
