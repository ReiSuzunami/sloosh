<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { confirm } from '@tauri-apps/plugin-dialog';
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
        title: 'Checking setup',
        description: '',
        action: null,
        actionLabel: null,
      };
    }
    if (!snapshot) {
      return {
        tone: 'unavailable',
        title: 'Status unavailable',
        description: 'Refresh to check setup.',
        action: 'refresh',
        actionLabel: 'Try again',
      };
    }
    if (!snapshot.skillReady) {
      return {
        tone: 'blocked',
        title: 'Agent Skill required',
        description: 'Install the Agent Skill in Setup.',
        action: 'setup',
        actionLabel: 'Continue setup',
      };
    }
    if (!snapshot.daemon.online) {
      return {
        tone: 'blocked',
        title: 'Daemon offline',
        description: snapshot.daemon.error ?? 'Check the daemon in Setup.',
        action: 'setup',
        actionLabel: 'Review setup',
      };
    }
    if (!snapshot.vaultExists) {
      return {
        tone: 'blocked',
        title: 'Vault required',
        description: 'Create a vault with a Master Password.',
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
      title: 'Setup complete',
      description: '',
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
      success = `Idle timeout set to ${minutes} minute${minutes === 1 ? '' : 's'}.`;
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

  async function setDangerousBypassMode() {
    if (activeAction !== null || snapshot?.dangerousBypassMode == null) return;
    const enabled = !snapshot.dangerousBypassMode;
    activeAction = 'set_dangerous_bypass_mode';
    error = null;
    success = null;
    try {
      const accepted = await confirm(
        enabled
          ? 'All clients under your macOS account:\n• All host access, without lease requests, scope limits, or renewal.\n• Unknown host keys trusted — risk of man-in-the-middle attacks.\n• Vault credentials usable without manual unlock, including after restart or cache expiry.\n\nUses the existing Sloosh Keychain credential. Access failures return an error, without a popup. SSH authentication is still required.\nApplies on the next daemon start; stays enabled until disabled.\nRestarting ends sessions, forwards, and leases.'
          : 'Applies on the next daemon start.\n\n• Default system SSH Agent-only requests still authorize automatically.\n• Previously trusted host keys remain trusted.\n• Restarting ends sessions, forwards, and leases.',
        { title: enabled ? 'Enable Dangerous Bypass Mode?' : 'Disable Dangerous Bypass Mode?', kind: 'warning', okLabel: enabled ? 'Enable on next start' : 'Disable on next start', cancelLabel: 'Cancel' },
      );
      if (!accepted) return;
      snapshot = await invoke<AppSnapshot>('set_dangerous_bypass_mode', { enabled });
      success = 'Saved for the next daemon start.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      activeAction = null;
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
            <h2 id="readiness-heading">{snapshot ? `${readiness.title} · ${setupProgress}/4` : readiness.title}</h2>
            {#if readiness.description}<p>{readiness.description}</p>{/if}
          </div>
          {#if readiness.action && readiness.actionLabel}
            <button class="secondary-button" onclick={handleReadinessAction}>
              {readiness.actionLabel} <ChevronRight size={16} />
            </button>
          {/if}
        </div>

        {#if snapshot && readiness.tone === 'blocked'}
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
            <span>Approval method</span>
            <strong>{localApprovalReady ? 'Ready' : 'Required'}</strong>
          </li>
        </ul>
        {/if}
      </section>

      <section class="activity-strip" aria-labelledby="activity-heading">
        <div>
          <h2 id="activity-heading">Activity</h2>
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
          <span><strong>Diagnostics</strong></span>
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
      <p class="approval-note">Approval is required except for default system SSH Agent-only requests or active bypass.</p>
      <section class="settings-list" aria-labelledby="approval-heading">
        <h2 id="approval-heading" class="sr-only">Approval methods</h2>
        <div class="setting-row">
          <div class="setting-icon"><Fingerprint size={20} /></div>
          <div class="setting-copy">
            <h3>Touch ID</h3>
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
            {#if approvalBlocker && snapshot?.pin.state !== 'ready'}<span class="constraint">{approvalBlocker}</span>{/if}
          </div>
          <div class="setting-actions">
            <span class:enabled={snapshot?.pin.state === 'ready'} class="state-label">{pinLabel()}</span>
            {#if snapshot?.pin.state === 'error'}
              <span class="state-detail" title={snapshot.pin.error ?? undefined}>Check local state</span>
            {:else if snapshot?.pin.state === 'ready' || snapshot?.pin.state === 'locked'}
              <button
                class="secondary-button danger-button"
                aria-label="Disable PIN"
                disabled={activeAction !== null}
                onclick={() => runAction('disable_pin', 'Approval PIN disabled.')}
              >{activeAction === 'disable_pin' ? 'Disabling...' : 'Disable'}</button>
            {:else}
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
          <div class="setting-icon"><LockKeyhole size={20} /></div>
          <div class="setting-copy"><h3>Master Password</h3><p>Required to change approval settings.</p></div>
          <span class:enabled={snapshot?.vaultExists} class="state-label">{snapshot?.vaultExists ? 'Set' : 'Not set'}</span>
        </div>

        <div class="setting-row">
          <div class="setting-icon"><Clock3 size={20} /></div>
          <div class="setting-copy">
            <h3>Idle timeout</h3>
            <p>Auto-locks the desktop vault; expires normal-mode idle leases.</p>
          </div>
          <div class="setting-actions">
            <label class="compact-select">
              <span class="sr-only">Idle timeout</span>
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

      <section class="danger-zone" aria-labelledby="bypass-heading">
        <div>
          <h2 id="bypass-heading">Dangerous Bypass Mode</h2>
          <p>All host access for every client under your macOS account. No leases or renewal; unknown host keys are trusted automatically.</p>
          <p class="bypass-risk">First connections risk man-in-the-middle attacks.</p>
          <p><strong>Saved: {snapshot?.dangerousBypassMode == null ? 'Unavailable' : snapshot.dangerousBypassMode ? 'Enabled' : 'Disabled'}</strong> · Applies on the next daemon start.</p>
          <details class="bypass-details">
            <summary>Restart and credential details</summary>
            <dl class="compact-facts">
              <div><dt>Restart</dt><dd>Ends sessions, forwards and leases</dd></div>
              <div><dt>Known keys</dt><dd>Changes still fail</dd></div>
              <div><dt>Credentials</dt><dd>Automatically unlocked from the existing Sloosh Keychain credential; access failures return an error without a popup</dd></div>
              <div><dt>Cache</dt><dd>Idle timeout; eight-hour maximum, then automatic re-unlock. Locking Hosts does not clear it.</dd></div>
            </dl>
          </details>
        </div>
        <button
          class="secondary-button danger-button"
          disabled={snapshot?.dangerousBypassMode == null || activeAction !== null}
          onclick={setDangerousBypassMode}
        >{activeAction === 'set_dangerous_bypass_mode' ? 'Saving...' : snapshot?.dangerousBypassMode ? 'Disable on next start' : 'Enable on next start'}</button>
      </section>

    {:else}
      <section class="setup-header" aria-labelledby="setup-heading">
        <div>
          <h2 id="setup-heading">{setupComplete ? 'Setup complete' : 'Setup checklist'}</h2>
        </div>
        <span>{setupProgress}/4</span>
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
            <h3>Approval method</h3>
            <p>
              {localApprovalReady && snapshot?.touchIdEnrolled
                ? 'Touch ID enabled'
                : localApprovalReady && snapshot?.pin.state === 'ready'
                  ? 'Sloosh PIN enabled'
                  : 'Choose Touch ID or Sloosh PIN'}
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
          <h2 id="keychain-dialog-title">Set up {pendingApprovalMethod === 'touch_id' ? 'Touch ID' : 'Sloosh PIN'}</h2>
        </div>
      </header>

      <p id="keychain-dialog-description" class="keychain-description">
        Saves your vault Master Password in login Keychain for local authentication.
      </p>

      <div class="keychain-access">
        <p>If macOS asks about <strong>Sloosh Approval</strong>:</p>
        <dl class="compact-facts">
          <div><dt>Allow</dt><dd>One-time access</dd></div>
          <div><dt>Always Allow</dt><dd>Future access to this item</dd></div>
        </dl>
      </div>

      <p class="keychain-note">Does not grant SSH access or import SSH keys.</p>

      <footer>
        <button type="button" class="secondary-button" onclick={dismissApprovalSetup}>Cancel</button>
        <button type="button" class="primary-button" onclick={continueApprovalSetup}>
          Continue
        </button>
      </footer>
    </div>
  </dialog>
{/if}
