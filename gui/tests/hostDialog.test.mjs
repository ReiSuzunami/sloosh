import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parse } from 'svelte/compiler';

const source = await readFile(new URL('../src/HostManager.svelte', import.meta.url), 'utf8');
const { fragment } = parse(source, { modern: true });

function collectDialogs(node, dialogs = []) {
  if (!node || typeof node !== 'object') return dialogs;
  if (node.type === 'RegularElement' && node.name === 'dialog') dialogs.push(node);

  for (const value of Object.values(node)) {
    if (Array.isArray(value)) value.forEach((child) => collectDialogs(child, dialogs));
    else collectDialogs(value, dialogs);
  }

  return dialogs;
}

function staticAttribute(element, name) {
  const attribute = element.attributes.find((candidate) => candidate.name === name);
  return attribute?.value?.length === 1 && attribute.value[0].type === 'Text'
    ? attribute.value[0].data
    : null;
}

function closeHandler(labelledBy) {
  const dialog = collectDialogs(fragment).find(
    (candidate) => staticAttribute(candidate, 'aria-labelledby') === labelledBy,
  );
  assert.ok(dialog, `dialog labelled by ${labelledBy} exists`);

  const handler = dialog.attributes.find((attribute) => attribute.name === 'onclose');
  assert.ok(handler, `${labelledBy} handles native dialog closure`);
  return handler.value;
}

test('host dialogs clear component state after native Escape closes them', () => {
  for (const labelledBy of ['host-dialog-title', 'remove-host-title']) {
    const handler = closeHandler(labelledBy);
    assert.equal(handler.type, 'ExpressionTag');
    assert.equal(handler.expression.type, 'Identifier');
    assert.equal(handler.expression.name, 'closeDialog');
  }
});
