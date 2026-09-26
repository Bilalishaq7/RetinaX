// Functional test for patient-card.js (run with Node.js)

// ---- Shim minimal browser globals ----
global.document = {
  readyState: 'complete',
  querySelectorAll: () => [],
  addEventListener: () => {},
  createElement: function (tag) {
    const el = {
      _tag: tag,
      className: '',
      innerHTML: '',
      dataset: {},
      style: {},
      setAttribute: function (k, v) { this['_attr_' + k] = v; },
      getAttribute: function (k) { return this['_attr_' + k] || null; },
      appendChild: function () {},
      querySelectorAll: function () { return []; },
      querySelector: function (sel) {
        if (sel === '.patient-card-component') return this._cardChild || null;
        return null;
      },
      parentNode: null,
      removeChild: function () {},
      classList: {
        _cls: '',
        add: function (c) { el.className += (el.className ? ' ' : '') + c; },
        remove: function (c) { el.className = el.className.replace(new RegExp('\\b' + c + '\\b', 'g'), '').trim(); },
        contains: function (c) { return el.className.split(' ').indexOf(c) !== -1; },
      },
    };
    return el;
  },
};
global.window = global;
global.HTMLElement = function () {};

const PatientCard = require('./patient-card.js');

// Mock HTMLElement factory
function MockEl(dataset) {
  this.dataset = dataset || {};
  this._children = [];
  this.innerHTML = '';
  this.appendChild = function (el) {
    this._children.push(el);
    el.parentNode = this;
  };
  this.querySelector = function (sel) {
    if (sel === '.patient-card-component') {
      return this._children.find(c => c.className.includes('patient-card-component')) || null;
    }
    return null;
  };
  this.getAttribute = function () { return null; };
  this.setAttribute = function () {};
}
MockEl.prototype = Object.create(HTMLElement.prototype);

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`✓ ${name}`);
  } catch (err) {
    failed++;
    console.error(`✗ ${name}`);
    console.error(`  ${err.message}`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  Tests
// ══════════════════════════════════════════════════════════════════════════════

test('PatientCard constructor creates instance', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, { patientName: 'Alice' });
  assert(pc instanceof PatientCard, 'should create PatientCard instance');
  assert(pc._mount === mount, 'should store mount element');
});

test('PatientCard throws TypeError for invalid mount', () => {
  let threw = false;
  try {
    new PatientCard(null, {});
  } catch (err) {
    threw = err instanceof TypeError;
  }
  assert(threw, 'should throw TypeError for non-HTMLElement mount');
});

test('PatientCard renders with programmatic options', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientId: 'P123',
    patientName: 'Bob Smith',
    age: 45,
    gender: 'M',
  });
  const card = mount.querySelector('.patient-card-component');
  assert(card !== null, 'should render patient-card-component');
  assert(card.innerHTML.includes('Bob Smith'), 'should include patient name');
  assert(card.innerHTML.includes('P123'), 'should include patient ID');
});

test('PatientCard reads from data-* attributes', () => {
  const mount = new MockEl({
    patientId: 'P456',
    patientName: 'Charlie Brown',
    age: '30',
    gender: 'M',
  });
  const pc = new PatientCard(mount);
  assert(pc._cfg.patientId === 'P456', 'should read patientId from dataset');
  assert(pc._cfg.patientName === 'Charlie Brown', 'should read patientName from dataset');
  assert(pc._cfg.age === 30, 'should parse age as number');
});

test('PatientCard handles missing optional data gracefully', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientName: 'Diana',
  });
  assert(pc._cfg.patientId === 'N/A', 'should default patientId');
  assert(pc._cfg.conditions.length === 0, 'should default to empty conditions');
  assert(pc._cfg.prescriptions.length === 0, 'should default to empty prescriptions');
});

test('PatientCard parses conditions from JSON string', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientName: 'Eve',
    conditions: '["Myopia", "Astigmatism"]',
  });
  assert(pc._cfg.conditions.length === 2, 'should parse conditions array');
  assert(pc._cfg.conditions[0] === 'Myopia', 'should have correct condition');
});

test('PatientCard parses prescriptions from array', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientName: 'Frank',
    prescriptions: [
      { type: 'OD', sphere: '-2.50', cylinder: '-0.75', axis: '180' },
    ],
  });
  assert(pc._cfg.prescriptions.length === 1, 'should store prescriptions');
  assert(pc._cfg.prescriptions[0].type === 'OD', 'should have correct prescription type');
});

test('PatientCard.showLoading() sets loading state', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, { patientName: 'Grace' });
  pc.showLoading();
  const card = mount.querySelector('.patient-card-component');
  assert(card.classList.contains('is-loading'), 'should add is-loading class');
  assert(card.innerHTML.includes('pc-skel'), 'should show skeleton HTML');
});

test('PatientCard.showError() displays error message', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, { patientName: 'Henry' });
  pc.showError('Connection failed');
  const card = mount.querySelector('.patient-card-component');
  assert(card.innerHTML.includes('Connection failed'), 'should show error message');
  assert(card.innerHTML.includes('⚠️'), 'should show error icon');
});

test('PatientCard.update() re-renders with new data', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, { patientName: 'Ivy', age: 25 });
  pc.update({ age: 26, recentExams: 3 });
  assert(pc._cfg.age === 26, 'should update age');
  assert(pc._cfg.recentExams === 3, 'should update recentExams');
  const card = mount.querySelector('.patient-card-component');
  assert(card.innerHTML.includes('26'), 'should render updated age');
});

test('PatientCard.destroy() removes card from DOM', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, { patientName: 'Jack' });
  const card = mount.querySelector('.patient-card-component');
  assert(card !== null, 'card should exist before destroy');
  
  // Mock removeChild
  card.parentNode = mount;
  mount.removeChild = function (child) {
    const idx = this._children.indexOf(child);
    if (idx !== -1) this._children.splice(idx, 1);
  };
  
  pc.destroy();
  assert(pc._card === null, 'should clear _card reference');
  assert(pc._mount === null, 'should clear _mount reference');
});

test('PatientCard renders access level badge', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientName: 'Karen',
    accessLevel: 'Admin',
  });
  const card = mount.querySelector('.patient-card-component');
  assert(card.innerHTML.includes('Admin'), 'should show access level');
  assert(card.innerHTML.includes('patient-card__access-badge'), 'should have badge class');
});

test('PatientCard respects showSensitive flag', () => {
  // Test with explicit showSensitive: true
  const mount1 = new MockEl();
  const pc1 = new PatientCard(mount1, {
    patientName: 'Mary',
    prescriptions: [{ type: 'OD', sphere: '-1.50' }],
    showSensitive: true,
  });
  const card1 = mount1.querySelector('.patient-card-component');
  assert(card1.innerHTML.includes('Current Prescription'), 'should show prescriptions when showSensitive=true');
  assert(card1.innerHTML.includes('SPH:'), 'should show prescription details');
  
  // Test with explicit showSensitive: false (as boolean)
  const mount2 = new MockEl({ showSensitive: 'false' });
  const pc2 = new PatientCard(mount2, {
    patientName: 'Larry',
    prescriptions: [{ type: 'OD', sphere: '-1.50' }],
  });
  // Access the actual config to verify it was parsed correctly
  assert(pc2._cfg.showSensitive === false, 'should parse showSensitive=false from dataset');
});

test('PatientCard handles no conditions with message', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientName: 'Nancy',
    conditions: [],
  });
  const card = mount.querySelector('.patient-card-component');
  assert(card.innerHTML.includes('No conditions recorded'), 'should show no conditions message');
});

test('PatientCard escapes HTML in patient data', () => {
  const mount = new MockEl();
  const pc = new PatientCard(mount, {
    patientName: '<script>alert("xss")</script>',
    careProvider: '<img src=x onerror=alert(1)>',
  });
  const card = mount.querySelector('.patient-card-component');
  assert(!card.innerHTML.includes('<script>'), 'should escape script tags');
  assert(card.innerHTML.includes('&lt;script&gt;'), 'should HTML-encode script');
  assert(!card.innerHTML.includes('<img src=x'), 'should escape img tags');
});

// ══════════════════════════════════════════════════════════════════════════════
//  Summary
// ══════════════════════════════════════════════════════════════════════════════

console.log('');
console.log(`Tests: ${passed + failed}`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  process.exit(1);
}
