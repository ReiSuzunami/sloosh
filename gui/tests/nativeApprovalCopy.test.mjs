import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(
  new URL('../../packaging/macos/native-approval.swift', import.meta.url),
  'utf8',
);

test('PIN submission names approval and desktop unlock separately', () => {
  const approvalStart = source.indexOf('switch selectedMethod');
  const approval = source.slice(
    approvalStart,
    source.indexOf('case .masterPassword:', approvalStart),
  );
  const unlock = source.slice(
    source.indexOf('case "begin_pin_unlock":'),
    source.indexOf('case "enroll":'),
  );
  assert.match(approval, /promptPin\([\s\S]*submitTitle: "Approve"/);
  assert.match(unlock, /promptPin\([\s\S]*submitTitle: "Unlock"/);
  assert.match(source, /alert\.addButton\(withTitle: submitTitle\)/);
});
