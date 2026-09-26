/* ==========================================================================
   Micro-tests for Frontend JS utils.js Date Formatting Functions
   Runs with Node.js test runner: node --test website/utils.test.js
   ========================================================================== */

const test = require('node:test');
const assert = require('node:assert/strict');
const RetinaXUtils = require('./utils.js');

test('utils.js — parseDateInput', async (t) => {
  await t.test('parses Date object', () => {
    const d = new Date('2026-09-24T12:00:00Z');
    const result = RetinaXUtils.parseDateInput(d);
    assert.strictEqual(result.toISOString(), '2026-09-24T12:00:00.000Z');
  });

  await t.test('parses Soroban timestamp in seconds', () => {
    // 1786062300 = 2026-08-07T00:25:00.000Z
    const result = RetinaXUtils.parseDateInput(1786062300);
    assert.strictEqual(result.toISOString(), '2026-08-07T00:25:00.000Z');
  });

  await t.test('parses timestamp in milliseconds', () => {
    const ms = 1786062300000;
    const result = RetinaXUtils.parseDateInput(ms);
    assert.strictEqual(result.toISOString(), '2026-08-07T00:25:00.000Z');
  });

  await t.test('parses ISO date string', () => {
    const result = RetinaXUtils.parseDateInput('2026-08-06T23:45:00Z');
    assert.ok(result instanceof Date);
    assert.strictEqual(result.toISOString(), '2026-08-06T23:45:00.000Z');
  });

  await t.test('handles invalid inputs gracefully', () => {
    assert.strictEqual(RetinaXUtils.parseDateInput(null), null);
    assert.strictEqual(RetinaXUtils.parseDateInput(undefined), null);
    assert.strictEqual(RetinaXUtils.parseDateInput('invalid-date'), null);
    assert.strictEqual(RetinaXUtils.parseDateInput(NaN), null);
  });
});

test('utils.js — truncateAddress', async (t) => {
  await t.test('truncates standard Stellar address (56 chars)', () => {
    const addr = 'GCZJM2KLV4LHX6SQQ3JY4OVKCQH4XLXJXS6QIVTGQXVHXKZXKP5ABCD';
    const result = RetinaXUtils.truncateAddress(addr);
    assert.strictEqual(result, 'GCZJM2...ABCD');
  });

  await t.test('truncates Soroban contract address (56 chars)', () => {
    const addr = 'CDLZFC3SYJYDZT7K67VZ56P6GDIZ67K67VZ56P6GDIZ67K67VZ9B2A';
    const result = RetinaXUtils.truncateAddress(addr);
    assert.strictEqual(result, 'CDLZFC...9B2A');
  });

  await t.test('uses custom prefix length', () => {
    const addr = 'GCZJM2KLV4LHX6SQQ3JY4OVKCQH4XLXJXS6QIVTGQXVHXKZXKP5ABCD';
    const result = RetinaXUtils.truncateAddress(addr, 8, 4);
    assert.strictEqual(result, 'GCZJM2KL...ABCD');
  });

  await t.test('uses custom suffix length', () => {
    const addr = 'GCZJM2KLV4LHX6SQQ3JY4OVKCQH4XLXJXS6QIVTGQXVHXKZXKP5ABCD';
    const result = RetinaXUtils.truncateAddress(addr, 6, 6);
    assert.strictEqual(result, 'GCZJM2...P5ABCD');
  });

  await t.test('does not truncate short addresses', () => {
    const shortAddr = 'ABC123XYZ';
    const result = RetinaXUtils.truncateAddress(shortAddr, 6, 4);
    assert.strictEqual(result, 'ABC123XYZ');
  });

  await t.test('handles empty string', () => {
    const result = RetinaXUtils.truncateAddress('');
    assert.strictEqual(result, '');
  });

  await t.test('handles non-string input', () => {
    assert.strictEqual(RetinaXUtils.truncateAddress(null), '');
    assert.strictEqual(RetinaXUtils.truncateAddress(undefined), '');
    assert.strictEqual(RetinaXUtils.truncateAddress(12345), '');
    assert.strictEqual(RetinaXUtils.truncateAddress({}), '');
  });

  await t.test('handles address exactly at cutoff length', () => {
    const addr = '0123456789'; // 10 chars, prefix=6, suffix=4
    const result = RetinaXUtils.truncateAddress(addr, 6, 4);
    assert.strictEqual(result, '0123456789');
  });

  await t.test('truncates with zero prefix or suffix', () => {
    const addr = 'GCZJM2KLV4LHX6SQQ3JY4OVKCQH4XLXJXS6QIVTGQXVHXKZXKP5ABCD';
    const result1 = RetinaXUtils.truncateAddress(addr, 0, 4);
    assert.strictEqual(result1, '...ABCD');
    
    const result2 = RetinaXUtils.truncateAddress(addr, 6, 0);
    assert.strictEqual(result2, 'GCZJM2...');
  });
});

test('utils.js — formatDate', async (t) => {
  await t.test('formats default YYYY-MM-DD', () => {
    const dateStr = RetinaXUtils.formatDate('2026-09-24T00:00:00Z');
    assert.strictEqual(dateStr, '2026-09-24');
  });

  await t.test('formats MMM DD, YYYY', () => {
    const dateStr = RetinaXUtils.formatDate('2026-09-24T00:00:00Z', 'MMM DD, YYYY');
    assert.strictEqual(dateStr, 'Sep 24, 2026');
  });

  await t.test('formats Soroban timestamp in seconds', () => {
    const dateStr = RetinaXUtils.formatDate(1786062300, 'YYYY-MM-DD');
    assert.strictEqual(dateStr, '2026-08-07');
  });

  await t.test('returns "Invalid Date" for bad inputs', () => {
    assert.strictEqual(RetinaXUtils.formatDate('not-a-date'), 'Invalid Date');
    assert.strictEqual(RetinaXUtils.formatDate(null), 'Invalid Date');
  });
});

test('utils.js — formatTimestamp', async (t) => {
  await t.test('formats Soroban ledger timestamp with time UTC', () => {
    // 1786062300 => 2026-08-07 00:25:00 UTC
    const formatted = RetinaXUtils.formatTimestamp(1786062300, true);
    assert.strictEqual(formatted, '2026-08-07 00:25:00 UTC');
  });

  await t.test('formats Soroban ledger timestamp date only', () => {
    const formatted = RetinaXUtils.formatTimestamp(1786062300, false);
    assert.strictEqual(formatted, '2026-08-07');
  });

  await t.test('returns "Invalid Date" for invalid timestamp', () => {
    assert.strictEqual(RetinaXUtils.formatTimestamp('abc'), 'Invalid Date');
  });
});

test('utils.js — formatFHIRDate', async (t) => {
  await t.test('formats date to FHIR v4 ISO 8601 UTC timestamp', () => {
    const fhirDate = RetinaXUtils.formatFHIRDate('2026-08-06T23:45:00Z');
    assert.strictEqual(fhirDate, '2026-08-06T23:45:00.000Z');
  });

  await t.test('formats numeric timestamp to FHIR v4 format', () => {
    const fhirDate = RetinaXUtils.formatFHIRDate(1786062300);
    assert.strictEqual(fhirDate, '2026-08-07T00:25:00.000Z');
  });

  await t.test('returns "Invalid Date" for invalid input', () => {
    assert.strictEqual(RetinaXUtils.formatFHIRDate(null), 'Invalid Date');
  });
});

test('utils.js — formatRelativeTime', async (t) => {
  const refTime = new Date('2026-09-24T12:00:00Z').getTime();

  await t.test('returns "just now" for times within 30 seconds', () => {
    const recent = new Date('2026-09-24T11:59:45Z').getTime();
    assert.strictEqual(RetinaXUtils.formatRelativeTime(recent, refTime), 'just now');
  });

  await t.test('formats minutes ago', () => {
    const past = new Date('2026-09-24T11:50:00Z').getTime(); // 10 mins ago
    assert.strictEqual(RetinaXUtils.formatRelativeTime(past, refTime), '10 minutes ago');
  });

  await t.test('formats singular minute ago', () => {
    const past = new Date('2026-09-24T11:59:00Z').getTime(); // 1 min ago
    assert.strictEqual(RetinaXUtils.formatRelativeTime(past, refTime), '1 minute ago');
  });

  await t.test('formats hours in future', () => {
    const future = new Date('2026-09-24T14:00:00Z').getTime(); // in 2 hours
    assert.strictEqual(RetinaXUtils.formatRelativeTime(future, refTime), 'in 2 hours');
  });

  await t.test('formats days ago', () => {
    const past = new Date('2026-09-22T12:00:00Z').getTime(); // 2 days ago
    assert.strictEqual(RetinaXUtils.formatRelativeTime(past, refTime), '2 days ago');
  });

  await t.test('handles invalid date inputs', () => {
    assert.strictEqual(RetinaXUtils.formatRelativeTime('invalid', refTime), 'Invalid Date');
  });
});

test('utils.js — isExpired', async (t) => {
  const current = new Date('2026-09-24T12:00:00Z').getTime();

  await t.test('returns true if expiry is in the past', () => {
    const past = new Date('2026-09-24T11:00:00Z').getTime();
    assert.strictEqual(RetinaXUtils.isExpired(past, current), true);
  });

  await t.test('returns false if expiry is in the future', () => {
    const future = new Date('2026-09-24T13:00:00Z').getTime();
    assert.strictEqual(RetinaXUtils.isExpired(future, current), false);
  });

  await t.test('returns true if expiry equals current time', () => {
    assert.strictEqual(RetinaXUtils.isExpired(current, current), true);
  });

  await t.test('returns true for invalid expiry', () => {
    assert.strictEqual(RetinaXUtils.isExpired('invalid', current), true);
  });
});

test('utils.js — formatDuration', async (t) => {
  await t.test('formats hours and minutes', () => {
    assert.strictEqual(RetinaXUtils.formatDuration(86400), '24 Hours');
    assert.strictEqual(RetinaXUtils.formatDuration(5400), '1 Hour 30 Mins');
  });

  await t.test('formats minutes only', () => {
    assert.strictEqual(RetinaXUtils.formatDuration(300), '5 Mins');
    assert.strictEqual(RetinaXUtils.formatDuration(60), '1 Min');
  });

  await t.test('formats seconds only', () => {
    assert.strictEqual(RetinaXUtils.formatDuration(45), '45 Secs');
  });

  await t.test('handles invalid or zero duration', () => {
    assert.strictEqual(RetinaXUtils.formatDuration(0), '0 Mins');
    assert.strictEqual(RetinaXUtils.formatDuration(-10), '0 Mins');
    assert.strictEqual(RetinaXUtils.formatDuration(null), '0 Mins');
  });
});
