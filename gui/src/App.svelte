<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import {
    Check,
    ChevronRight,
    CircleAlert,
    Clock3,
    Fingerprint,
    Gauge,
    KeyRound,
    LockKeyhole,
    RefreshCw,
    Server,
    Settings2,
    ShieldCheck,
    TerminalSquare,
    X,
  } from '@lucide/svelte';
  import HostManager from './HostManager.svelte';
  import type { AppSnapshot, VaultUnlockSnapshot, View } from './types';

  type ReadinessAction = 'refresh' | 'setup' | null;
  type ReadinessTone = 'checking' | 'blocked' | 'ready' | 'unavailable';
  type ApprovalMethod = 'touch_id' | 'pin';

  let view = $state<View>('overview');
  let snapshot = $state<AppSnapshot | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let success = $state<string | null>(null);
  let activeAction = $state<string | null>(null);
  let pendingApprovalMethod = $state<ApprovalMethod | null>(null);
  let reducedMotion = $state(false);
  const enterDuration = $derived(reducedMotion ? 0 : 180);
  const exitDuration = $derived(reducedMotion ? 0 : 120);

  const localApprovalReady = $derived(
    Boolean(
      snapshot?.vaultExists &&
        (snapshot?.touchIdEnrolled || snapshot?.pin.state === 'ready'),
    ),
  );
  const setupComplete = $derived(
    Boolean(
      snapshot?.daemon.online &&
        snapshot?.skillReady &&
        snapshot?.vaultExists &&
        localApprovalReady,
    ),
  );
  const setupProgress = $derived(
    Number(Boolean(snapshot?.skillReady)) +
      Number(Boolean(snapshot?.daemon.online)) +
      Number(Boolean(snapshot?.vaultExists)) +
      Number(localApprovalReady),
  );
  const approvalBlocker = $derived(
    !snapshot
      ? 'Waiting for local status.'
      : !snapshot.nativeApprovalAvailable
        ? 'Native approval is unavailable in this installation.'
        : !snapshot.vaultExists
          ? 'Create the credential vault first.'
          : null,
  );
  const readiness = $derived.by((): {
    tone: ReadinessTone;
    title: string;
    description: string;
    action: ReadinessAction;
    actionLabel: string | null;
  } => {
    if (!snapshot && loading) {
      return {
        tone: 'checking',
        title: 'Checking local security',
        description: 'Reading daemon and approval state.',
        action: null,
        actionLabel: null,
      };
    }
    if (!snapshot) {
      return {
        tone: 'unavailable',
        title: 'Status unavailable',
        description: 'Local security state could not be read.',
        action: 'refresh',
        actionLabel: 'Try again',
      };
    }
    if (!snapshot.skillReady) {
      return {
        tone: 'blocked',
        title: 'Agent Skill required',
        description: 'The embedded Agent Skill is not installed.',
        action: 'setup',
        actionLabel: 'Continue setup',
      };
    }
    if (!snapshot.daemon.online) {
      return {
        tone: 'blocked',
        title: 'Daemon offline',
        description: snapshot.daemon.error ?? 'The local daemon is not reachable.',
        action: 'setup',
        actionLabel: 'Review setup',
      };
    }
    if (!snapshot.vaultExists) {
      return {
        tone: 'blocked',
        title: 'Vault required',
        description: 'The credential vault has not been created.',
        action: 'setup',
        actionLabel: 'Create vault',
      };
    }
    if (!localApprovalReady) {
      return {
        tone: 'blocked',
        title: 'Approval method required',
        description: 'Enable Touch ID or a six-digit approval PIN.',
        action: 'setup',
        actionLabel: 'Choose a method',
      };
    }
    return {
      tone: 'ready',
      title: 'Ready for approval',
      description: 'All local approval requirements are satisfied.',
      action: null,
      actionLabel: null,
    };
  });

  async function refresh() {
    if (activeAction !== null) return;
    loading = true;
    error = null;
    try {
      snapshot = await invoke<AppSnapshot>('get_app_snapshot');
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      loading = false;
    }
  }

  async function runAction(command: string, completedMessage: string) {
    activeAction = command;
    error = null;
    success = null;
    try {
      snapshot = await invoke<AppSnapshot>(command);
      success = completedMessage;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      activeAction = null;
    }
  }

  function modal(node: HTMLDialogElement) {
    node.showModal();
    requestAnimationFrame(() => {
      node.querySelector<HTMLButtonElement>('.primary-button')?.focus();
    });
  }

  function beginApprovalSetup(method: ApprovalMethod) {
    if (activeAction !== null || approvalBlocker) return;
    error = null;
    success = null;
    pendingApprovalMethod = method;
  }

  function dismissApprovalSetup() {
    pendingApprovalMethod = null;
  }

  function continueApprovalSetup() {
    const method = pendingApprovalMethod;
    if (!method) return;
    dismissApprovalSetup();
    queueMicrotask(() => {
      if (method === 'touch_id') {
        void runAction('enable_touch_id', 'Touch ID approval enabled.');
      } else {
        void runAction('enable_pin', 'Approval PIN enabled.');
      }
    });
  }

  async function setVaultTimeout(event: Event) {
    if (activeAction !== null) return;
    const minutes = Number((event.currentTarget as HTMLSelectElement).value);
    activeAction = 'set_vault_timeout';
    error = null;
    success = null;
    try {
      snapshot = await invoke<AppSnapshot>('set_vault_timeout', { minutes });
      success = `Vault timeout set to ${minutes} minute${minutes === 1 ? '' : 's'}.`;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      activeAction = null;
    }
  }

  function handleReadinessAction() {
    if (readiness.action === 'refresh') {
      void refresh();
    } else if (readiness.action === 'setup') {
      view = 'setup';
    }
  }

  function updateVaultUnlock(vaultUnlock: VaultUnlockSnapshot) {
    if (snapshot) {
      snapshot = {
        ...snapshot,
        vaultUnlock,
        vaultTimeoutMinutes: vaultUnlock.idleTimeoutMinutes,
      };
    }
  }

  function pinLabel(): string {
    switch (snapshot?.pin.state) {
      case 'ready':
        return 'Enabled';
      case 'locked':
        return `Locked - ${snapshot.pin.remainingSecs ?? 0}s`;
      case 'disabled':
        return 'Disabled';
      case 'error':
        return 'State unavailable';
      default:
        return 'Not configured';
    }
  }

  function formatUptime(seconds: number | null): string {
    if (seconds === null) return 'Unavailable';
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  }

  onMount(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const updateMotion = () => (reducedMotion = query.matches);
    updateMotion();
    query.addEventListener('change', updateMotion);
    void refresh();
    return () => query.removeEventListener('change', updateMotion);
  });
</script>

<svelte:head>
  <title>Sloosh</title>
</svelte:head>

<div class="app-shell">
  <a class="skip-link" href="#main-content">Skip to content</a>
  <aside class="sidebar" aria-label="Primary navigation">
    <div class="brand">
      <picture class="brand-icon">
        <source srcset="/icon-dark.png" media="(prefers-color-scheme: dark)" />
        <img src="/icon-light.png" alt="" />
      </picture>
      <span>Sloosh</span>
    </div>

    <nav>
      <button
        class:active={view === 'overview'}
        aria-current={view === 'overview' ? 'page' : undefined}
        aria-label="Overview"
        data-label="Overview"
        title="Overview"
        onclick={() => (view = 'overview')}
      >
        <Gauge size={18} strokeWidth={1.8} />
        <span class="nav-label">Overview</span>
      </button>
      <button
        class:active={view === 'hosts'}
        aria-current={view === 'hosts' ? 'page' : undefined}
        aria-label="Hosts"
        data-label="Hosts"
        title="Hosts"
        onclick={() => (view = 'hosts')}
      >
        <Server size={18} strokeWidth={1.8} />
        <span class="nav-label">Hosts</span>
      </button>
      <button
        class:active={view === 'security'}
        aria-current={view === 'security' ? 'page' : undefined}
        aria-label="Security"
        data-label="Security"
        title="Security"
        onclick={() => (view = 'security')}
      >
        <ShieldCheck size={18} strokeWidth={1.8} />
        <span class="nav-label">Security</span>
      </button>
      <button
        class:active={view === 'setup'}
        aria-current={view === 'setup' ? 'page' : undefined}
        aria-label="Setup"
        data-label="Setup"
        title="Setup"
        onclick={() => (view = 'setup')}
      >
        <Settings2 size={18} strokeWidth={1.8} />
        <span class="nav-label">Setup</span>
      </button>
    </nav>

    <div class="sidebar-status" role="status">
      <span
        class="status-dot"
        class:online={snapshot?.daemon.online}
        class:checking={loading && !snapshot}
      ></span>
      <span>
        {loading && !snapshot
          ? 'Checking status'
          : snapshot?.daemon.online
            ? 'Daemon online'
            : snapshot
              ? 'Daemon offline'
              : 'Status unavailable'}
      </span>
    </div>
  </aside>

  <main id="main-content">
    <header class="topbar">
      <div>
        <p class="context-label">{view === 'hosts' ? 'Credential vault' : 'SSH approval'}</p>
        <h1>
          {view === 'overview'
            ? 'Overview'
            : view === 'hosts'
              ? 'Hosts'
              : view === 'security'
                ? 'Security'
                : 'Setup'}
        </h1>
      </div>
      <button
        class="icon-button"
        onclick={refresh}
        disabled={loading || activeAction !== null}
        aria-label="Refresh status"
        title="Refresh status"
      >
        <RefreshCw size={18} class={loading ? 'spin' : undefined} />
      </button>
    </header>

    {#if error}
      <div class="notice error" role="alert" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
        <CircleAlert size={18} />
        <span>{error}</span>
      </div>
    {/if}
    {#if success}
      <div class="notice success" role="status" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
        <Check size={18} />
        <span>{success}</span>
      </div>
    {/if}

    {#key view}
      <div class="view-panel" in:fade={{ duration: enterDuration }}>
      {#if view === 'overview'}
      <section class="readiness-panel {readiness.tone}" aria-labelledby="readiness-heading">
        <div class="readiness-primary">
          <div class="readiness-mark" class:ready={readiness.tone === 'ready'}>
            {#if readiness.tone === 'ready'}
              <Check size={22} />
            {:else if readiness.tone === 'checking'}
              <RefreshCw size={20} class="spin" />
            {:else}
              <LockKeyhole size={21} />
            {/if}
          </div>
          <div class="readiness-copy">
            <p class="section-kicker">Security readiness</p>
            <h2 id="readiness-heading">{readiness.title}</h2>
            <p>{readiness.description}</p>
          </div>
          {#if readiness.action && readiness.actionLabel}
            <button class="secondary-button" onclick={handleReadinessAction}>
              {readiness.actionLabel} <ChevronRight size={16} />
            </button>
          {/if}
        </div>

        <ul class="readiness-checks" aria-label="Setup requirements">
          <li class:complete={snapshot?.skillReady}>
            <span class="requirement-mark">{#if snapshot?.skillReady}<Check size={12} />{/if}</span>
            <span>Agent Skill</span>
            <strong>{snapshot?.skillReady ? 'Ready' : 'Required'}</strong>
          </li>
          <li class:complete={snapshot?.daemon.online}>
            <span class="requirement-mark">{#if snapshot?.daemon.online}<Check size={12} />{/if}</span>
            <span>Daemon</span>
            <strong>{snapshot?.daemon.online ? 'Online' : loading && !snapshot ? 'Checking' : 'Offline'}</strong>
          </li>
          <li class:complete={snapshot?.vaultExists}>
            <span class="requirement-mark">{#if snapshot?.vaultExists}<Check size={12} />{/if}</span>
            <span>Vault</span>
            <strong>{snapshot?.vaultExists ? 'Ready' : 'Required'}</strong>
          </li>
          <li class:complete={localApprovalReady}>
            <span class="requirement-mark">{#if localApprovalReady}<Check size={12} />{/if}</span>
            <span>Keychain approval</span>
            <strong>{localApprovalReady ? 'Ready' : 'Required'}</strong>
          </li>
        </ul>
      </section>

      <section class="activity-strip" aria-labelledby="activity-heading">
        <div>
          <p class="section-kicker">Current activity</p>
          <h2 id="activity-heading">Local runtime</h2>
        </div>
        <dl>
          <div><dt>Sessions</dt><dd>{snapshot?.daemon.sessions ?? '-'}</dd></div>
          <div><dt>Active leases</dt><dd>{snapshot?.daemon.leases ?? '-'}</dd></div>
          <div><dt>Uptime</dt><dd>{formatUptime(snapshot?.daemon.uptimeSecs ?? null)}</dd></div>
        </dl>
      </section>

      <details class="diagnostics">
        <summary>
          <ChevronRight size={16} />
          <span><strong>Diagnostics</strong><small>Runtime, protocol, and installation details</small></span>
        </summary>
        <dl class="detail-list">
          <div><dt>Daemon</dt><dd class:positive={snapshot?.daemon.online}>{snapshot?.daemon.online ? `Online - PID ${snapshot.daemon.pid}` : 'Offline'}</dd></div>
          <div><dt>Version</dt><dd>{snapshot?.daemon.version ?? 'Unavailable'}</dd></div>
          <div><dt>Wire protocol</dt><dd>{snapshot?.daemon.wireProtocol ?? 'Unavailable'}</dd></div>
          <div><dt>Credential vault</dt><dd class:positive={snapshot?.vaultExists}>{snapshot?.vaultExists ? 'Initialized' : 'Not initialized'}</dd></div>
          <div><dt>Native approval</dt><dd class:positive={snapshot?.nativeApprovalAvailable}>{snapshot?.nativeApprovalAvailable ? 'Available' : 'Unavailable'}</dd></div>
          <div class="path-row"><dt>Daemon</dt><dd title={snapshot?.daemonPath}>{snapshot?.daemonPath ?? 'Unavailable'}</dd></div>
        </dl>
        {#if snapshot?.daemon.error}
          <p class="inline-error">{snapshot.daemon.error}</p>
        {/if}
      </details>
    {:else if view === 'hosts'}
      <HostManager {snapshot} onSetup={() => (view = 'setup')} onUnlockChange={updateVaultUnlock} />
    {:else if view === 'security'}
      <section class="page-intro" aria-labelledby="approval-heading">
        <p class="section-kicker">Local verification</p>
        <h2 id="approval-heading">Approval methods</h2>
        <p>Password, key-file, and custom-agent scopes show three direct approval buttons. System SSH-agent-only scopes authorize automatically.</p>
      </section>

      <section class="settings-list" aria-label="Approval methods">
        <div class="setting-row">
          <div class="setting-icon"><LockKeyhole size={20} /></div>
          <div class="setting-copy">
            <h3>macOS login Keychain</h3>
            <p>Protects a local vault credential; SSH private keys stay where you configured them</p>
          </div>
          <span class:enabled={localApprovalReady} class="state-label">
            {localApprovalReady ? 'Configured' : 'Set up with a method'}
          </span>
        </div>

        <div class="setting-row">
          <div class="setting-icon"><Fingerprint size={20} /></div>
          <div class="setting-copy">
            <h3>Touch ID</h3>
            <p>System biometric authentication</p>
            {#if approvalBlocker}<span class="constraint">{approvalBlocker}</span>{/if}
          </div>
          <div class="setting-actions">
            <span class:enabled={snapshot?.vaultExists && snapshot?.touchIdEnrolled} class="state-label">
              {snapshot?.vaultExists && snapshot?.touchIdEnrolled
                ? 'Enabled'
                : snapshot?.nativeApprovalAvailable
                  ? 'Not enabled'
                  : 'Unavailable'}
            </span>
            <button
              class="secondary-button"
              disabled={Boolean(approvalBlocker) || activeAction !== null}
              title={approvalBlocker ?? undefined}
              onclick={() => beginApprovalSetup('touch_id')}
            >
              {activeAction === 'enable_touch_id' ? 'Enabling...' : snapshot?.touchIdEnrolled ? 'Re-enroll' : 'Enable'}
            </button>
          </div>
        </div>

        <div class="setting-row">
          <div class="setting-icon"><KeyRound size={20} /></div>
          <div class="setting-copy">
            <h3>Sloosh PIN</h3>
            <p>Unlocks this app and approves confirmed SSH requests</p>
            {#if approvalBlocker && snapshot?.pin.state !== 'ready'}<span class="constraint">{approvalBlocker}</span>{/if}
          </div>
          <div class="setting-actions">
            <span class:enabled={snapshot?.pin.state === 'ready'} class="state-label">{pinLabel()}</span>
            {#if snapshot?.pin.state === 'error'}
              <span class="state-detail" title={snapshot.pin.error ?? undefined}>Check local state</span>
            {:else if snapshot?.pin.state !== 'ready' && snapshot?.pin.state !== 'locked'}
              <button
                class="secondary-button"
                disabled={Boolean(approvalBlocker) || activeAction !== null}
                title={approvalBlocker ?? undefined}
                onclick={() => beginApprovalSetup('pin')}
              >
                {activeAction === 'enable_pin' ? 'Enabling...' : snapshot?.pin.state === 'disabled' ? 'Re-enable' : 'Enable'}
              </button>
            {/if}
          </div>
        </div>

        <div class="setting-row">
          <div class="setting-icon"><Clock3 size={20} /></div>
          <div class="setting-copy">
            <h3>Vault timeout</h3>
            <p>Locks the desktop vault and idle CLI/Agent leases</p>
          </div>
          <div class="setting-actions">
            <label class="compact-select">
              <span class="sr-only">Vault timeout</span>
              <select
                value={snapshot?.vaultTimeoutMinutes ?? 15}
                disabled={!snapshot?.vaultExists || activeAction !== null}
                onchange={setVaultTimeout}
              >
                <option value="1">1 minute</option>
                <option value="5">5 minutes</option>
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
              </select>
            </label>
          </div>
        </div>
      </section>

      <section class="section-block" aria-labelledby="recovery-heading">
        <div class="section-heading"><h2 id="recovery-heading">Recovery</h2></div>
        <div class="setting-row compact">
          <div class="setting-copy"><h3>Master Password</h3><p>Required to change protected approval settings.</p></div>
          <span class:enabled={snapshot?.vaultExists} class="state-label">{snapshot?.vaultExists ? 'Set' : 'Not set'}</span>
        </div>
      </section>

      {#if snapshot?.pin.state === 'ready' || snapshot?.pin.state === 'locked'}
        <section class="danger-zone" aria-labelledby="danger-heading">
          <div>
            <h2 id="danger-heading">Disable approval PIN</h2>
            <p>Touch ID remains available when configured.</p>
          </div>
          <button
            class="secondary-button danger-button"
            disabled={activeAction !== null}
            onclick={() => runAction('disable_pin', 'Approval PIN disabled.')}
          >
            {activeAction === 'disable_pin' ? 'Disabling...' : 'Disable PIN'}
          </button>
        </section>
      {/if}
    {:else}
      <section class="setup-header" aria-labelledby="setup-heading">
        <div>
          <p class="section-kicker">Guided configuration</p>
          <h2 id="setup-heading">Local setup</h2>
          <p>{setupComplete ? 'All required steps are complete.' : 'Complete the remaining security steps.'}</p>
        </div>
        <span>{setupProgress} of 4</span>
      </section>

      <ol class="setup-flow">
        <li class:complete={snapshot?.skillReady} class:current={!snapshot?.skillReady}>
          <span class="step-number">{#if snapshot?.skillReady}<Check size={14} />{:else}1{/if}</span>
          <div class="step-copy"><h3>Agent Skill</h3><p>{snapshot?.skillReady ? 'Installed and current' : 'Installation required'}</p></div>
          {#if !snapshot?.skillReady}
            <button
              class="secondary-button"
              disabled={activeAction !== null}
              onclick={() => runAction('install_skill', 'Agent Skill installed.')}
            >{activeAction === 'install_skill' ? 'Installing...' : 'Install'}</button>
          {/if}
        </li>

        <li class:complete={snapshot?.daemon.online} class:current={snapshot?.skillReady && !snapshot?.daemon.online}>
          <span class="step-number">{#if snapshot?.daemon.online}<Check size={14} />{:else}2{/if}</span>
          <div class="step-copy">
            <h3>Daemon</h3>
            <p>{snapshot?.daemon.online ? 'Connected' : 'Not reachable'}</p>
            {#if snapshot?.daemon.error}<span class="constraint">{snapshot.daemon.error}</span>{/if}
          </div>
          {#if snapshot?.daemon.online}
            <TerminalSquare size={18} />
          {:else}
            <button
              class="secondary-button"
              disabled={loading || activeAction !== null}
              onclick={refresh}
            >
              <RefreshCw size={15} class={loading ? 'spin' : undefined} /> Check
            </button>
          {/if}
        </li>

        <li class:complete={snapshot?.vaultExists} class:current={snapshot?.skillReady && snapshot?.daemon.online && !snapshot?.vaultExists}>
          <span class="step-number">{#if snapshot?.vaultExists}<Check size={14} />{:else}3{/if}</span>
          <div class="step-copy">
            <h3>Credential vault</h3>
            <p>{snapshot?.vaultExists ? 'Initialized' : 'Master Password required'}</p>
            {#if !snapshot?.nativeApprovalAvailable && !snapshot?.vaultExists}
              <span class="constraint">Native setup is unavailable in this installation.</span>
            {/if}
          </div>
          {#if snapshot?.vaultExists}
            <LockKeyhole size={18} />
          {:else}
            <button
              class="secondary-button"
              disabled={!snapshot?.nativeApprovalAvailable || activeAction !== null}
              title={!snapshot?.nativeApprovalAvailable ? 'Native setup is unavailable in this installation.' : undefined}
              onclick={() => runAction('initialize_vault', 'Credential vault created.')}
            >{activeAction === 'initialize_vault' ? 'Creating...' : 'Create'}</button>
          {/if}
        </li>

        <li class:complete={localApprovalReady} class:current={Boolean(snapshot?.vaultExists) && !localApprovalReady}>
          <span class="step-number">{#if localApprovalReady}<Check size={14} />{:else}4{/if}</span>
          <div class="step-copy">
            <h3>Keychain &amp; local approval</h3>
            <p>
              {localApprovalReady && snapshot?.touchIdEnrolled
                ? 'Keychain protected with Touch ID'
                : localApprovalReady && snapshot?.pin.state === 'ready'
                  ? 'Keychain protected with Sloosh PIN'
                  : 'Choose how the native helper unlocks the protected credential'}
            </p>
            {#if approvalBlocker && !localApprovalReady}<span class="constraint">{approvalBlocker}</span>{/if}
          </div>
          {#if localApprovalReady}
            <Fingerprint size={18} />
          {:else}
            <div class="step-actions">
              <button
                class="secondary-button"
                disabled={Boolean(approvalBlocker) || activeAction !== null}
                title={approvalBlocker ?? undefined}
                onclick={() => beginApprovalSetup('touch_id')}
              >{activeAction === 'enable_touch_id' ? 'Enabling...' : 'Touch ID'}</button>
              <button
                class="secondary-button"
                disabled={Boolean(approvalBlocker) || activeAction !== null}
                title={approvalBlocker ?? undefined}
                onclick={() => beginApprovalSetup('pin')}
              >{activeAction === 'enable_pin' ? 'Enabling...' : 'PIN'}</button>
            </div>
          {/if}
        </li>
      </ol>
      {/if}
      </div>
    {/key}
  </main>
</div>

{#if pendingApprovalMethod}
  <dialog
    use:modal
    class="host-dialog keychain-dialog"
    aria-modal="true"
    aria-labelledby="keychain-dialog-title"
    aria-describedby="keychain-dialog-description"
    oncancel={(event) => {
      event.preventDefault();
      dismissApprovalSetup();
    }}
    onkeydown={(event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        dismissApprovalSetup();
      }
    }}
    in:scale={{ start: reducedMotion ? 1 : 0.985, duration: enterDuration, opacity: 0 }}
    out:fade={{ duration: exitDuration }}
  >
    <div class="keychain-onboarding">
      <header>
        <button
          type="button"
          class="icon-button dialog-close"
          onclick={dismissApprovalSetup}
          aria-label="Close"
          title="Close"
        ><X size={17} /></button>
        <div>
          <p class="section-kicker">macOS protection</p>
          <h2 id="keychain-dialog-title">Allow Sloosh to use your login Keychain</h2>
        </div>
      </header>

      <div class="keychain-summary">
        <span class="keychain-mark"><LockKeyhole size={22} /></span>
        <p id="keychain-dialog-description">
          Sloosh stores a protected copy of your vault Master Password in the macOS login Keychain.
          The bundled native helper uses it only after you authenticate.
        </p>
      </div>

      <ol class="keychain-steps">
        <li><span>1</span><p>Confirm your Master Password in a native Sloosh window.</p></li>
        <li>
          <span>2</span>
          <p>
            If macOS asks whether <strong>Sloosh Approval</strong> may access the Keychain item,
            choose <strong>Always Allow</strong> on your Mac to avoid repeated prompts, or
            <strong>Allow</strong> for one-time access.
          </p>
        </li>
        <li>
          <span>3</span>
          <p>
            {pendingApprovalMethod === 'touch_id'
              ? 'Authenticate with Touch ID. Adding or removing fingerprints requires re-enrollment.'
              : 'Create and confirm a six-digit Sloosh PIN. Its verifier stays on this Mac.'}
          </p>
        </li>
      </ol>

      <div class="keychain-boundary">
        <ShieldCheck size={17} />
        <p>
          This does not import SSH private keys or approve a host. Every future request still shows
          its exact host scope before authentication. Master Password and PIN stay out of this WebView.
        </p>
      </div>

      <footer>
        <button type="button" class="secondary-button" onclick={dismissApprovalSetup}>Cancel</button>
        <button type="button" class="primary-button" onclick={continueApprovalSetup}>
          {pendingApprovalMethod === 'touch_id' ? 'Continue with Touch ID' : 'Continue to create PIN'}
          <ChevronRight size={16} />
        </button>
      </footer>
    </div>
  </dialog>
{/if}
