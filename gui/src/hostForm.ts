import type { HostSummary } from './types';

export type HostMode = 'add' | 'edit' | 'delete' | null;

export type HostForm = {
  alias: string;
  hostname: string;
  port: string | number;
  user: string;
  auth: HostSummary['auth'];
  password: string;
  keyFile: string;
  changeAuth: boolean;
  routeMode: 'direct' | 'managed_host' | 'proxy_jump';
  managedHost: string;
  proxyJump: string;
};

export type HostCommandInput = HostSummary & {
  password: string | null;
  keyFile: string | null;
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
    alias: '',
    hostname: '',
    port: '',
    user: '',
    auth: 'agent',
    password: '',
    keyFile: '',
    changeAuth: false,
    routeMode: 'direct',
    managedHost: '',
    proxyJump: '',
  };
}

export function hostFormFromSummary(host: HostSummary): HostForm {
  return {
    alias: host.alias,
    hostname: host.hostname,
    port: host.port?.toString() ?? '',
    user: host.user ?? '',
    auth: host.auth,
    password: '',
    keyFile: '',
    changeAuth: false,
    routeMode: host.route.type,
    managedHost: host.route.type === 'managed_host' ? host.route.alias : '',
    proxyJump: host.route.type === 'proxy_jump' ? host.route.spec : '',
  };
}

export function buildHostSubmission(form: HostForm, mode: HostMode): HostSubmissionResult {
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
  if (changesAuth && form.auth === 'key_file' && !form.keyFile.trim()) {
    return { ok: false, error: 'Choose a private key file.' };
  }
  if (changesAuth && form.auth === 'password' && !form.password) {
    return { ok: false, error: 'Enter the SSH password.' };
  }

  const route =
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

  const host: HostSummary = {
    alias,
    hostname,
    port,
    user: form.user.trim() || null,
    auth: form.auth,
    route,
  };
  return {
    ok: true,
    value: {
      host,
      commandHost: {
        ...host,
        password: changesAuth && form.auth === 'password' ? form.password : null,
        keyFile: changesAuth && form.auth === 'key_file' ? form.keyFile.trim() : null,
      },
      changeAuth: mode === 'edit' && form.changeAuth,
    },
  };
}
