<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import {
    Check,
    ChevronRight,
    CircleAlert,
    Fingerprint,
    Gauge,
    KeyRound,
    LockKeyhole,
    RefreshCw,
    Settings2,
    ShieldCheck,
    TerminalSquare,
  } from '@lucide/svelte';
  import type { AppSnapshot, View } from './types';

  let view = $state<View>('overview');
  let snapshot = $state<AppSnapshot | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let success = $state<string | null>(null);
  let activeAction = $state<string | null>(null);

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

  async function refresh() {
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

  function pinLabel(): string {
    switch (snapshot?.pin.state) {
      case 'ready': return 'Enabled';
      case 'locked': return `Locked · ${snapshot.pin.remainingSecs ?? 0}s`;
      case 'disabled': return 'Disabled';
      case 'error': return 'State unavailable';
      default: return 'Not configured';
    }
  }

  $effect(() => {
    void refresh();
  });

  function formatUptime(seconds: number | null): string {
    if (seconds === null) return 'Unavailable';
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  }
</script>

<svelte:head>
  <title>Sloosh</title>
</svelte:head>

<div class="app-shell">
  <a class="skip-link" href="#main-content">Skip to content</a>
  <aside class="sidebar" aria-label="Primary navigation">
    <div class="brand">
      <img src="/icon.png" alt="" />
      <span>Sloosh</span>
    </div>

    <nav>
      <button class:active={view === 'overview'} onclick={() => (view = 'overview')}>
        <Gauge size={18} strokeWidth={1.8} />
        Overview
      </button>
      <button class:active={view === 'security'} onclick={() => (view = 'security')}>
        <ShieldCheck size={18} strokeWidth={1.8} />
        Security
      </button>
      <button class:active={view === 'setup'} onclick={() => (view = 'setup')}>
        <Settings2 size={18} strokeWidth={1.8} />
        Setup
      </button>
    </nav>

    <div class="sidebar-status">
      <span class:online={snapshot?.daemon.online} class="status-dot"></span>
      <span>{snapshot?.daemon.online ? 'Daemon online' : 'Daemon offline'}</span>
    </div>
  </aside>

  <main id="main-content">
    <header class="topbar">
      <div>
        <p class="context-label">Local control</p>
        <h1>{view === 'overview' ? 'Overview' : view === 'security' ? 'Security' : 'Setup'}</h1>
      </div>
      <button class="icon-button" onclick={refresh} disabled={loading} aria-label="Refresh status" title="Refresh status">
        <RefreshCw size={18} class={loading ? 'spin' : undefined} />
      </button>
    </header>

    {#if error}
      <div class="notice error" role="alert">
        <CircleAlert size={18} />
        <span>{error}</span>
      </div>
    {/if}
    {#if success}
      <div class="notice success" role="status">
        <Check size={18} />
        <span>{success}</span>
      </div>
    {/if}

    {#if view === 'overview'}
      <section class="overview-status" aria-labelledby="readiness-heading">
        <div class:ready={setupComplete} class="readiness-mark">
          {#if setupComplete}<Check size={22} />{:else}<LockKeyhole size={21} />{/if}
        </div>
        <div>
          <h2 id="readiness-heading">{setupComplete ? 'Ready for approval' : 'Setup required'}</h2>
          <p>{setupComplete ? 'Local approval is available.' : 'Complete the missing security steps.'}</p>
        </div>
        {#if !setupComplete}
          <button class="secondary-button" onclick={() => (view = 'setup')}>
            Review setup <ChevronRight size={16} />
          </button>
        {/if}
      </section>

      <section class="section-block" aria-labelledby="runtime-heading">
        <div class="section-heading">
          <h2 id="runtime-heading">Runtime</h2>
          <span>{snapshot?.daemon.version ?? 'Not connected'}</span>
        </div>
        <dl class="detail-list">
          <div>
            <dt>Daemon</dt>
            <dd class:positive={snapshot?.daemon.online}>{snapshot?.daemon.online ? `Online · PID ${snapshot.daemon.pid}` : 'Offline'}</dd>
          </div>
          <div><dt>Uptime</dt><dd>{formatUptime(snapshot?.daemon.uptimeSecs ?? null)}</dd></div>
          <div><dt>Sessions</dt><dd>{snapshot?.daemon.sessions ?? 0}</dd></div>
          <div><dt>Active leases</dt><dd>{snapshot?.daemon.leases ?? 0}</dd></div>
          <div><dt>Wire protocol</dt><dd>{snapshot?.daemon.wireProtocol ?? 'Unavailable'}</dd></div>
        </dl>
        {#if snapshot?.daemon.error}
          <p class="inline-error">{snapshot.daemon.error}</p>
        {/if}
      </section>

      <section class="section-block" aria-labelledby="installation-heading">
        <div class="section-heading"><h2 id="installation-heading">Installation</h2></div>
        <dl class="detail-list">
          <div><dt>Credential vault</dt><dd class:positive={snapshot?.vaultExists}>{snapshot?.vaultExists ? 'Initialized' : 'Not initialized'}</dd></div>
          <div><dt>Native approval</dt><dd class:positive={snapshot?.nativeApprovalAvailable}>{snapshot?.nativeApprovalAvailable ? 'Available' : 'Unavailable'}</dd></div>
          <div class="path-row"><dt>CLI</dt><dd title={snapshot?.cliPath}>{snapshot?.cliPath ?? 'Unavailable'}</dd></div>
        </dl>
      </section>
    {:else if view === 'security'}
      <section class="section-block security-list" aria-labelledby="approval-heading">
        <div class="section-heading">
          <div><h2 id="approval-heading">Approval methods</h2><p>Used after host access is confirmed.</p></div>
        </div>
        <div class="setting-row">
          <div class="setting-icon"><Fingerprint size={20} /></div>
          <div class="setting-copy"><h3>Touch ID</h3><p>System authentication</p></div>
          <div class="setting-actions">
            <span class:enabled={snapshot?.vaultExists && snapshot?.touchIdEnrolled} class="state-label">{snapshot?.vaultExists && snapshot?.touchIdEnrolled ? 'Enabled' : snapshot?.nativeApprovalAvailable ? 'Not enabled' : 'Unavailable'}</span>
            <button
              class="secondary-button"
              disabled={!snapshot?.nativeApprovalAvailable || activeAction !== null || !snapshot?.vaultExists}
              onclick={() => runAction('enable_touch_id', 'Touch ID approval enabled.')}
            >{activeAction === 'enable_touch_id' ? 'Enabling...' : snapshot?.touchIdEnrolled ? 'Re-enroll' : 'Enable'}</button>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-icon"><KeyRound size={20} /></div>
          <div class="setting-copy"><h3>Approval PIN</h3><p>Optional local fallback</p></div>
          <div class="setting-actions">
            <span class:enabled={snapshot?.pin.state === 'ready'} class="state-label">{pinLabel()}</span>
            {#if snapshot?.pin.state === 'ready' || snapshot?.pin.state === 'locked'}
              <button
                class="secondary-button danger-button"
                disabled={activeAction !== null}
                onclick={() => runAction('disable_pin', 'Approval PIN disabled.')}
              >{activeAction === 'disable_pin' ? 'Disabling...' : 'Disable'}</button>
            {:else if snapshot?.pin.state === 'error'}
              <span class="state-detail" title={snapshot.pin.error ?? undefined}>Check local state</span>
            {:else}
              <button
                class="secondary-button"
                disabled={!snapshot?.nativeApprovalAvailable || activeAction !== null || !snapshot?.vaultExists}
                onclick={() => runAction('enable_pin', 'Approval PIN enabled.')}
              >{activeAction === 'enable_pin' ? 'Enabling...' : snapshot?.pin.state === 'disabled' ? 'Re-enable' : 'Enable'}</button>
            {/if}
          </div>
        </div>
      </section>

      <section class="section-block" aria-labelledby="recovery-heading">
        <div class="section-heading"><h2 id="recovery-heading">Recovery</h2></div>
        <div class="setting-row compact">
          <div class="setting-copy"><h3>Master Password</h3><p>Required to recover or remove approval methods.</p></div>
          <span class:enabled={snapshot?.vaultExists} class="state-label">{snapshot?.vaultExists ? 'Set' : 'Not set'}</span>
        </div>
      </section>
    {:else}
      <section class="setup-flow" aria-labelledby="setup-heading">
        <div class="section-heading">
          <div><h2 id="setup-heading">Local setup</h2><p>Complete each required step.</p></div>
        </div>
        <ol>
          <li class:complete={snapshot?.skillReady}>
            <span class="step-number">{snapshot?.skillReady ? '✓' : '1'}</span>
            <div><h3>Install Agent Skill</h3><p>{snapshot?.skillReady ? 'Skill is current' : 'Install the embedded Skill'}</p></div>
            {#if snapshot?.skillReady}
              <Check size={18} />
            {:else}
              <button
                class="secondary-button"
                disabled={activeAction !== null}
                onclick={() => runAction('install_skill', 'Agent Skill installed.')}
              >{activeAction === 'install_skill' ? 'Installing...' : 'Install'}</button>
            {/if}
          </li>
          <li class:complete={snapshot?.daemon.online}>
            <span class="step-number">{snapshot?.daemon.online ? '✓' : '2'}</span>
            <div><h3>Start daemon</h3><p>{snapshot?.daemon.online ? 'Connected' : 'Daemon could not be reached'}</p></div>
            <TerminalSquare size={18} />
          </li>
          <li class:complete={snapshot?.vaultExists}>
            <span class="step-number">{snapshot?.vaultExists ? '✓' : '3'}</span>
            <div><h3>Create credential vault</h3><p>{snapshot?.vaultExists ? 'Vault initialized' : 'Master Password required'}</p></div>
            {#if snapshot?.vaultExists}
              <LockKeyhole size={18} />
            {:else}
              <button
                class="secondary-button"
                disabled={!snapshot?.nativeApprovalAvailable || activeAction !== null}
                onclick={() => runAction('initialize_vault', 'Credential vault created.')}
              >{activeAction === 'initialize_vault' ? 'Creating...' : 'Create'}</button>
            {/if}
          </li>
          <li class:complete={localApprovalReady}>
            <span class="step-number">{localApprovalReady ? '✓' : '4'}</span>
            <div><h3>Enable local approval</h3><p>{localApprovalReady && snapshot?.touchIdEnrolled ? 'Touch ID enabled' : localApprovalReady && snapshot?.pin.state === 'ready' ? 'Approval PIN enabled' : 'Choose a method in Security'}</p></div>
            {#if localApprovalReady}
              <Fingerprint size={18} />
            {:else}
              <button class="secondary-button" onclick={() => (view = 'security')}>Choose</button>
            {/if}
          </li>
        </ol>
      </section>
    {/if}
  </main>
</div>
