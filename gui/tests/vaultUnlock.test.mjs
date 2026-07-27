import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

const source = await readFile(new URL('../src/vaultUnlock.ts', import.meta.url), 'utf8');
const javascript = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const vaultUnlock = await import(
  `data:text/javascript;base64,${Buffer.from(javascript).toString('base64')}`
);

test('focus status sync cannot supersede an active Touch ID unlock', async () => {
  let generation = 0;
  let state = 'locked';
  let releaseTouchId;
  const touchId = new Promise((resolve) => {
    releaseTouchId = resolve;
  });
  const activeAction = 'unlock_vault_with_touch_id';
  const unlockGeneration = ++generation;

  const unlock = (async () => {
    const next = await touchId;
    if (unlockGeneration === generation) state = next;
  })();

  const canStartFocusSync = vaultUnlock.canStartVaultUnlockStatusSync(false, activeAction);
  assert.equal(canStartFocusSync, false);
  if (canStartFocusSync) {
    const statusGeneration = ++generation;
    const staleStatus = 'locked';
    if (statusGeneration === generation) state = staleStatus;
  }

  releaseTouchId('unlocked');
  await unlock;

  assert.equal(state, 'unlocked');
});

test('status sync remains available outside native unlock prompts', () => {
  assert.equal(vaultUnlock.canStartVaultUnlockStatusSync(false, null), true);
  assert.equal(vaultUnlock.canStartVaultUnlockStatusSync(false, 'list_hosts'), true);
  assert.equal(vaultUnlock.canStartVaultUnlockStatusSync(true, null), false);
  assert.equal(
    vaultUnlock.canStartVaultUnlockStatusSync(false, 'unlock_vault_with_master'),
    false,
  );
  assert.equal(vaultUnlock.canStartVaultUnlockStatusSync(false, 'unlock_vault_with_pin'), false);
});
