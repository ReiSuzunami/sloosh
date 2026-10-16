import type { HostSummary } from './types';

export type HostMode = 'add' | 'edit' | 'delete' | null;

export type HostForm = {
  source: HostSummary['source'];
  alias: string;
  hostname: string;
  port: string | number;
  user: string;
  auth: HostSummary['auth'];
  password: string;
  keyFile: string;
  privateKey: string;
  changeAuth: boolean;
  routeMode: 'direct' | 'managed_host' | 'proxy_jump';
  managedHost: string;
  proxyJump: string;
};

export type HostCommandInput = HostSummary & {
  password: string | null;
  keyFile: string | null;
  privateKey: string | null;
  syncToAgent: boolean;
};

export type HostSubmission = {
  host: HostSummary;
  commandHost: HostCommandInput;
  changeAuth: boolean;
};

type HostSubmissionResult =
  | { ok: true; value: HostSubmission }
  | { ok: false; error: string };

export function emptyHostForm(): HostForm {
  return {
    source: 'ssh_config',
    alias: '',
    hostname: '',
    port: '',
    user: '',
    auth: 'agent',
    password: '',
    keyFile: '',
    privateKey: '',
    changeAuth: false,
    routeMode: 'direct',
    managedHost: '',
    proxyJump: '',
  };
}

export function hostFormFromSummary(host: HostSummary): HostForm {
  return {
    source: host.source,
    alias: host.alias,
    hostname: host.hostname,
    port: host.port?.toString() ?? '',
    user: host.user ?? '',
    auth: host.auth,
    password: '',
    keyFile: '',
    privateKey: '',
    changeAuth: false,
    routeMode: host.route.type,
    managedHost: host.route.type === 'managed_host' ? host.route.alias : '',
    proxyJump: host.route.type === 'proxy_jump' ? host.route.spec : '',
  };
}

export function buildHostSubmission(
  form: HostForm,
  mode: HostMode,
  hosts: HostSummary[],
): HostSubmissionResult {
  if (mode !== 'add' && mode !== 'edit') {
    return { ok: false, error: 'Choose add or edit before saving a host.' };
  }

  const alias = form.alias.trim();
  const hostname = form.hostname.trim();
  if (!alias || !hostname) {
    return { ok: false, error: 'Alias and hostname are required.' };
  }

  const portValue = String(form.port).trim();
  const port = portValue ? Number(portValue) : null;
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    return { ok: false, error: 'Port must be an integer from 1 to 65535.' };
  }

  const changesAuth = mode === 'add' || form.changeAuth;
  const syncToAgent = changesAuth && form.source === 'ssh_config' && (form.auth === 'key_file' || form.auth === 'private_key');
  if (form.source === 'ssh_config' && form.auth === 'password') {
    return { ok: false, error: 'Password authentication belongs in the Sloosh vault.' };
  }
  if (changesAuth && form.source === 'vault' && form.auth === 'agent') {
    return { ok: false, error: 'Choose a vault credential, or add a system SSH host.' };
  }
  if (changesAuth && form.auth === 'private_key' && !form.privateKey.trim()) {
    return { ok: false, error: 'Paste a private key.' };
  }
  if (changesAuth && form.auth === 'key_file' && !form.keyFile.trim()) {
    return { ok: false, error: 'Choose a private key file.' };
  }
  if (changesAuth && form.auth === 'password' && !form.password) {
    return { ok: false, error: 'Enter the SSH password.' };
  }

  let route =
    form.routeMode === 'managed_host'
      ? { type: 'managed_host' as const, alias: form.managedHost.trim() }
      : form.routeMode === 'proxy_jump'
        ? { type: 'proxy_jump' as const, spec: form.proxyJump.trim() }
        : { type: 'direct' as const };
  if (route.type === 'managed_host' && !route.alias) {
    return { ok: false, error: 'Choose a managed host to route through.' };
  }
  if (route.type === 'managed_host' && route.alias === alias) {
    return { ok: false, error: 'A host cannot route through itself.' };
  }
  if (route.type === 'proxy_jump' && !route.spec) {
    return { ok: false, error: 'Enter an OpenSSH ProxyJump specification.' };
  }
  if (route.type === 'managed_host') {
    const jumpAlias = route.alias;
    const jump = hosts.find((host) => host.alias === jumpAlias);
    if (jump?.source === 'ssh_config') {
      route = { type: 'proxy_jump', spec: jumpAlias };
    }
  }

  const host: HostSummary = {
    source: form.source,
    editError: null,
    alias,
    hostname,
    port,
    user: form.user.trim() || null,
    auth: form.auth === 'agent' || syncToAgent ? 'agent' : form.auth,
    route,
  };
  return {
    ok: true,
    value: {
      host,
      commandHost: {
        ...host,
        auth: form.auth,
        privateKey: changesAuth && form.auth === 'private_key' ? form.privateKey : null,
        syncToAgent,
        password: changesAuth && form.auth === 'password' ? form.password : null,
        keyFile: changesAuth && form.auth === 'key_file' ? form.keyFile.trim() : null,
      },
      changeAuth: mode === 'edit' && form.changeAuth,
    },
  };
}
