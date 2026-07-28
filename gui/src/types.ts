export type DaemonSnapshot = {
  online: boolean;
  pid: number | null;
  version: string | null;
  wireProtocol: number | null;
  uptimeSecs: number | null;
  sessions: number;
  leases: number;
  error: string | null;
};

export type AppSnapshot = {
  platform: 'macos' | 'windows' | string;
  daemon: DaemonSnapshot;
  vaultExists: boolean;
  skillReady: boolean;
  nativeApprovalAvailable: boolean;
  touchIdEnrolled: boolean;
  pin: {
    state: 'not_configured' | 'ready' | 'locked' | 'disabled' | 'error';
    remainingSecs: number | null;
    error: string | null;
  };
  vaultUnlock: VaultUnlockSnapshot;
  vaultTimeoutMinutes: 1 | 5 | 15 | 30;
  daemonPath: string;
};

export type VaultUnlockSnapshot = {
  state: 'locked' | 'unlocked';
  method: 'master_password' | 'touch_id' | 'pin' | null;
  idleRemainingSecs: number | null;
  absoluteRemainingSecs: number | null;
  idleTimeoutMinutes: 1 | 5 | 15 | 30;
};

export type HostSummary = {
  alias: string;
  hostname: string;
  port: number | null;
  user: string | null;
  auth: 'agent' | 'password' | 'key_file';
  route:
    | { type: 'direct' }
    | { type: 'managed_host'; alias: string }
    | { type: 'proxy_jump'; spec: string };
};

export type View = 'overview' | 'hosts' | 'security' | 'setup';
