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

test('one connection test owns trust confirmation and continues afterward', () => {
  const trustDialog = source.slice(
    source.indexOf('{#if keyPreview}'),
    source.indexOf("{#if mode === 'delete'"),
  );
  assert.match(trustDialog, /'Trust and continue'/);
  assert.match(trustDialog, /'Replace and continue'/);
  assert.doesNotMatch(source, /aria-label=\{`Trust host key for/);
  const action = source.slice(source.indexOf('async function applyHostKeyAction'), source.indexOf('function endpoint'));
  assert.match(action, /if \(!result.preview\)/);
  assert.match(action, /invoke<string>\('test_host_connection'/);
  assert.match(action, /else error = errorMessage\(cause\)/);
});

test('adding a vault host offers inline unlock instead of disabling the destination', () => {
  const vaultRadio = source.match(/<input[^\n]+checked=\{form.source === 'vault'\}[^\n]*\/>/)?.[0];
  assert.ok(vaultRadio);
  assert.doesNotMatch(vaultRadio, /disabled/);
  const addDialog = source.slice(source.indexOf("{#if mode === 'add' || mode === 'edit'}"), source.indexOf('{#if keyPreview}'));
  assert.match(addDialog, /aria-label="Unlock vault for this host"/);
  assert.match(addDialog, /type="button"[^\n]+unlockHosts\('unlock_vault_with_master'\)/);
  assert.match(addDialog, /Unlock to save/);
  const unlockAction = source.slice(source.indexOf('async function unlockHosts'), source.indexOf('async function lockHosts'));
  assert.match(unlockAction, /formError = errorMessage\(cause\)/);
  assert.doesNotMatch(unlockAction, /closeDialog\(/);
});
