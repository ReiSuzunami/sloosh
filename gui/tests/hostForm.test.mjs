import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

const source = await readFile(new URL('../src/hostForm.ts', import.meta.url), 'utf8');
const javascript = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const hostForm = await import(
  `data:text/javascript;base64,${Buffer.from(javascript).toString('base64')}`
);

test('ordinary edits omit stale authentication fields', () => {
  const form = hostForm.hostFormFromSummary({
    source: 'vault',
    alias: 'web',
    hostname: 'web.internal',
    port: 22,
    user: 'deploy',
    auth: 'password',
    route: { type: 'direct' },
  });
  form.password = 'stale-password';
  form.keyFile = '/stale/key';
  form.privateKey = 'stale-private-key';
  form.syncToAgent = true;

  const result = hostForm.buildHostSubmission(form, 'edit');

  assert.equal(result.ok, true);
  assert.equal(result.value.commandHost.password, null);
  assert.equal(result.value.commandHost.keyFile, null);
  assert.equal(result.value.commandHost.privateKey, null);
  assert.equal(result.value.commandHost.syncToAgent, false);
  assert.equal(result.value.changeAuth, false);
});

test('add and explicit auth change send only the selected credential', () => {
  const add = hostForm.emptyHostForm();
  add.alias = 'bastion';
  add.hostname = 'bastion.internal';
  add.auth = 'password';
  add.source = 'vault';
  add.password = 'one-use-password';

  const added = hostForm.buildHostSubmission(add, 'add');
  assert.equal(added.ok, true);
  assert.equal(added.value.commandHost.password, 'one-use-password');
  assert.equal(added.value.commandHost.keyFile, null);

  const edit = hostForm.hostFormFromSummary(added.value.host);
  edit.changeAuth = true;
  edit.auth = 'key_file';
  edit.keyFile = '/Users/test/.ssh/id_ed25519';

  const changed = hostForm.buildHostSubmission(edit, 'edit');
  assert.equal(changed.ok, true);
  assert.equal(changed.value.commandHost.password, null);
  assert.equal(changed.value.commandHost.keyFile, '/Users/test/.ssh/id_ed25519');
  assert.equal(changed.value.changeAuth, true);
});

test('host validation rejects invalid port and routes', () => {
  const form = hostForm.emptyHostForm();
  form.alias = 'web';
  form.hostname = 'web.internal';
  form.port = '65536';
  assert.match(hostForm.buildHostSubmission(form, 'add').error, /Port/);

  form.port = '22';
  form.routeMode = 'managed_host';
  form.managedHost = 'web';
  assert.match(hostForm.buildHostSubmission(form, 'add').error, /cannot route through itself/);

  form.routeMode = 'proxy_jump';
  form.proxyJump = '   ';
  assert.match(hostForm.buildHostSubmission(form, 'add').error, /ProxyJump/);
});

test('numeric values from an input[type=number] are accepted', () => {
  const form = hostForm.emptyHostForm();
  form.alias = 'jump';
  form.hostname = 'jump.example.com';
  form.port = 56875;

  const result = hostForm.buildHostSubmission(form, 'add');

  assert.equal(result.ok, true);
  assert.equal(result.value.host.port, 56875);
});

test('pasted keys stay out of summaries and agent loading is opt-in', () => {
  const form = hostForm.emptyHostForm();
  form.alias = 'web';
  form.hostname = 'web.example';
  form.auth = 'private_key';
  form.source = 'vault';
  assert.match(hostForm.buildHostSubmission(form, 'add').error, /Paste/);
  form.privateKey = 'private-key-fixture';
  let result = hostForm.buildHostSubmission(form, 'add');
  assert.equal(result.value.commandHost.privateKey, 'private-key-fixture');
  assert.equal(result.value.commandHost.syncToAgent, false);
  assert.equal(JSON.stringify(result.value.host).includes('private-key-fixture'), false);
  form.source = 'ssh_config';
  result = hostForm.buildHostSubmission(form, 'add');
  assert.equal(result.value.commandHost.syncToAgent, true);
  assert.equal(result.value.commandHost.source, 'ssh_config');
  assert.equal(result.value.host.auth, 'agent');
  form.auth = 'agent';
  result = hostForm.buildHostSubmission(form, 'add');
  assert.equal(result.value.commandHost.privateKey, null);
  assert.equal(result.value.commandHost.syncToAgent, false);
});
