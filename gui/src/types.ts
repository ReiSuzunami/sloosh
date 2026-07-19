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
  cliPath: string;
};

export type View = 'overview' | 'security' | 'setup';
