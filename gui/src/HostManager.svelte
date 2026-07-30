<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { open } from '@tauri-apps/plugin-dialog';
  import { flip } from 'svelte/animate';
  import { onMount, untrack } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import {
    Cable,
    Check,
    CircleAlert,
    Copy,
    FileKey2,
    Fingerprint,
    FolderOpen,
    GitBranch,
    KeyRound,
    LockKeyhole,
    Pencil,
    Plus,
    RefreshCw,
    Server,
    ShieldCheck,
    Trash2,
    X,
  } from '@lucide/svelte';
  import {
    buildHostSubmission,
    emptyHostForm,
    hostFormFromSummary,
    type HostForm,
    type HostMode,
  } from './hostForm';
  import type {
    AppSnapshot,
    HostKeyActionResult,
    HostKeyPreview,
    HostSummary,
    VaultUnlockSnapshot,
  } from './types';
  import { canStartVaultUnlockStatusSync } from './vaultUnlock';

  let {
    snapshot,
    onSetup,
    onUnlockChange,
  }: {
    snapshot: AppSnapshot | null;
    onSetup: () => void;
    onUnlockChange: (unlock: VaultUnlockSnapshot) => void;
  } = $props();

  let hosts = $state<HostSummary[] | null>(null);
  let mode = $state<HostMode>(null);
  let selected = $state<HostSummary | null>(null);
  let activeAction = $state<string | null>(null);
  let error = $state<string | null>(null);
  let success = $state<string | null>(null);
  let formError = $state<string | null>(null);
  let form = $state<HostForm>(emptyHostForm());
  let keyPreview = $state<HostKeyPreview | null>(null);
  let keyPreviewMessage = $state<string | null>(null);
  let retryConnectionAlias = $state<string | null>(null);
  let reducedMotion = $state(false);
  let unlock = $state<VaultUnlockSnapshot>({
    state: 'locked',
    method: null,
    idleRemainingSecs: null,
    absoluteRemainingSecs: null,
    idleTimeoutMinutes: 15,
  });
  let lastActivityTouch = 0;
  let unlockGeneration = 0;
  let statusInFlight = false;
  let expirySyncRequested = false;
  let hostOperationGeneration = 0;
  const enterDuration = $derived(reducedMotion ? 0 : 180);
  const exitDuration = $derived(reducedMotion ? 0 : 120);
  const dependentHosts = $derived(
    selected
      ? (hosts ?? []).filter(
          (host) => host.route.type === 'managed_host' && host.route.alias === selected?.alias,
        )
      : [],
  );

  const blocker = $derived(
    !snapshot
      ? 'Local status is unavailable.'
      : !snapshot.daemon.online
        ? 'The local daemon must be online.'
        : !snapshot.vaultExists
          ? 'Create the credential vault first.'
          : !snapshot.nativeApprovalAvailable
            ? 'Native secure input is unavailable in this installation.'
            : null,
  );

  function errorMessage(cause: unknown): string {
    return cause instanceof Error ? cause.message : String(cause);
  }

  function modal(node: HTMLDialogElement) {
    node.showModal();
    requestAnimationFrame(() => {
      node
        .querySelector<HTMLElement>(
          'input:not(:disabled), button:not(:disabled), [tabindex]:not([tabindex="-1"])',
        )
        ?.focus();
    });
  }

  $effect(() => {
    const next = snapshot?.vaultUnlock;
    if (next) untrack(() => applyUnlock(next, false));
  });

  onMount(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => (reducedMotion = query.matches);
    update();
    query.addEventListener('change', update);
    const timer = window.setInterval(() => {
      if (unlock.state === 'unlocked') {
        const previousIdle = unlock.idleRemainingSecs ?? 0;
        const previousAbsolute = unlock.absoluteRemainingSecs ?? 0;
        unlock = {
          ...unlock,
          idleRemainingSecs: Math.max(0, previousIdle - 1),
          absoluteRemainingSecs: Math.max(0, previousAbsolute - 1),
        };
        const crossedDeadline =
          (previousIdle > 0 && (unlock.idleRemainingSecs ?? 0) === 0) ||
          (previousAbsolute > 0 && (unlock.absoluteRemainingSecs ?? 0) === 0);
        if (crossedDeadline && !expirySyncRequested) {
          expirySyncRequested = true;
          void syncUnlockStatus();
        }
      }
    }, 1000);
    const statusTimer = window.setInterval(() => void syncUnlockStatus(), 15_000);
    window.addEventListener('pointerdown', noteActivity, { passive: true });
    window.addEventListener('keydown', noteActivity);
    window.addEventListener('focus', syncUnlockStatus);
    return () => {
      query.removeEventListener('change', update);
      window.clearInterval(timer);
      window.clearInterval(statusTimer);
      window.removeEventListener('pointerdown', noteActivity);
      window.removeEventListener('keydown', noteActivity);
      window.removeEventListener('focus', syncUnlockStatus);
    };
  });

  function applyUnlock(next: VaultUnlockSnapshot, notify: boolean) {
    const wasLocked = unlock.state === 'locked';
    unlock = next;
    expirySyncRequested = false;
    if (notify) onUnlockChange(next);
    if (next.state === 'locked') {
      hostOperationGeneration += 1;
      hosts = null;
      form.password = '';
      mode = null;
      selected = null;
      formError = null;
      keyPreview = null;
      keyPreviewMessage = null;
      retryConnectionAlias = null;
    } else if (wasLocked && hosts === null && activeAction === null) {
      queueMicrotask(() => void loadHosts());
    }
  }

  function setUnlock(next: VaultUnlockSnapshot) {
    applyUnlock(next, true);
  }

  async function syncUnlockStatus() {
    if (!canStartVaultUnlockStatusSync(statusInFlight, activeAction)) return;
    const generation = ++unlockGeneration;
    statusInFlight = true;
    try {
      const next = await invoke<VaultUnlockSnapshot>('get_vault_unlock_status');
      if (generation === unlockGeneration) setUnlock(next);
    } catch {
      if (generation === unlockGeneration) {
        setUnlock({
          state: 'locked',
          method: null,
          idleRemainingSecs: null,
          absoluteRemainingSecs: null,
          idleTimeoutMinutes: snapshot?.vaultTimeoutMinutes ?? 15,
        });
      }
    } finally {
      statusInFlight = false;
    }
  }

  function noteActivity() {
    if (unlock.state !== 'unlocked') return;
    const now = Date.now();
    if (now - lastActivityTouch < 30_000) return;
    lastActivityTouch = now;
    const generation = ++unlockGeneration;
    void invoke<VaultUnlockSnapshot>('touch_vault_session')
      .then((next) => {
        if (generation === unlockGeneration) setUnlock(next);
      })
      .catch(() => syncUnlockStatus());
  }

  async function loadHosts() {
    if (activeAction !== null || blocker) return;
    activeAction = 'list_hosts';
    const operation = ++hostOperationGeneration;
    error = null;
    success = null;
    try {
      const nextHosts = await invoke<HostSummary[]>('list_hosts');
      if (operation === hostOperationGeneration && unlock.state === 'unlocked') {
        hosts = nextHosts;
      }
      await syncUnlockStatus();
    } catch (cause) {
      error = errorMessage(cause);
      await syncUnlockStatus();
    } finally {
      activeAction = null;
    }
  }

  async function unlockHosts(command: string) {
    if (activeAction !== null || blocker) return;
    activeAction = command;
    const generation = ++unlockGeneration;
    const operation = ++hostOperationGeneration;
    let refreshAfterFailure = false;
    error = null;
    success = null;
    try {
      const next = await invoke<VaultUnlockSnapshot>(command);
      if (generation !== unlockGeneration) return;
      setUnlock(next);
      const nextHosts = await invoke<HostSummary[]>('list_hosts');
      if (operation === hostOperationGeneration && unlock.state === 'unlocked') {
        hosts = nextHosts;
        success = 'Credential vault unlocked.';
      }
    } catch (cause) {
      error = errorMessage(cause);
      refreshAfterFailure = true;
    } finally {
      activeAction = null;
    }
    if (refreshAfterFailure) await syncUnlockStatus();
  }

  async function lockHosts() {
    if (activeAction !== null) return;
    activeAction = 'lock_vault';
    const generation = ++unlockGeneration;
    try {
      const next = await invoke<VaultUnlockSnapshot>('lock_vault');
      if (generation === unlockGeneration) {
        setUnlock(next);
        error = null;
        success = null;
      }
    } catch (cause) {
      error = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  function unlockMethodLabel(): string {
    if (unlock.method === 'touch_id') return 'Touch ID';
    if (unlock.method === 'pin') return 'Sloosh PIN';
    return 'Master Password';
  }

  function formatCountdown(seconds: number | null): string {
    const safe = Math.max(0, seconds ?? 0);
    const minutes = Math.floor(safe / 60);
    return `${minutes}:${String(safe % 60).padStart(2, '0')}`;
  }

  function openAdd() {
    selected = null;
    form = emptyHostForm();
    formError = null;
    mode = 'add';
  }

  function openEdit(host: HostSummary) {
    selected = host;
    form = hostFormFromSummary(host);
    formError = null;
    mode = 'edit';
  }

  function openDelete(host: HostSummary) {
    selected = host;
    formError = null;
    mode = 'delete';
  }

  function closeDialog() {
    form.password = '';
    form.keyFile = '';
    mode = null;
    selected = null;
    formError = null;
  }

  async function chooseKeyFile() {
    if (activeAction !== null) return;
    formError = null;
    try {
      const selection = await open({
        title: 'Choose SSH private key',
        multiple: false,
        directory: false,
      });
      if (typeof selection === 'string') form.keyFile = selection;
    } catch (cause) {
      formError = errorMessage(cause);
    }
  }

  async function saveHost() {
    if (activeAction !== null) return;
    let submission;
    try {
      submission = buildHostSubmission(form, mode);
    } catch (cause) {
      const message = errorMessage(cause);
      formError = message;
      return;
    }
    if (!submission.ok) {
      formError = submission.error;
      return;
    }
    const { host, commandHost, changeAuth } = submission.value;
    const command = mode === 'edit' ? 'update_host' : 'add_host';
    activeAction = command;
    const operation = ++hostOperationGeneration;
    formError = null;
    error = null;
    success = null;
    form.password = '';
    try {
      await invoke<void>(command, {
        host: commandHost,
        ...(command === 'update_host' ? { changeAuth } : {}),
      });
      if (operation === hostOperationGeneration && unlock.state === 'unlocked') {
        hosts = command === 'update_host'
          ? (hosts ?? []).map((entry) => entry.alias === host.alias ? host : entry)
          : [...(hosts ?? []), host].sort((left, right) => left.alias.localeCompare(right.alias));
        success = command === 'update_host' ? `Updated ${host.alias}.` : `Added ${host.alias}.`;
        mode = null;
        selected = null;
      }
    } catch (cause) {
      formError = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  async function removeHost() {
    if (!selected || activeAction !== null) return;
    const alias = selected.alias;
    activeAction = 'remove_host';
    const operation = ++hostOperationGeneration;
    formError = null;
    error = null;
    success = null;
    try {
      await invoke<void>('remove_host', { alias });
      if (operation === hostOperationGeneration && unlock.state === 'unlocked') {
        hosts = (hosts ?? []).filter((host) => host.alias !== alias);
        success = `Removed ${alias}.`;
        mode = null;
        selected = null;
      }
    } catch (cause) {
      formError = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  async function loadHostKeyPreview(alias: string): Promise<HostKeyPreview | null> {
    return invoke<HostKeyPreview | null>('preview_host_key', { alias });
  }

  async function previewHostKey(host: HostSummary, retryConnection = false) {
    if (activeAction !== null) return;
    activeAction = `preview_host_key:${host.alias}`;
    error = null;
    success = null;
    keyPreviewMessage = null;
    retryConnectionAlias = retryConnection ? host.alias : null;
    try {
      const preview = await loadHostKeyPreview(host.alias);
      if (preview) {
        keyPreview = preview;
      } else {
        keyPreview = null;
        retryConnectionAlias = null;
        success = `All host keys for ${host.alias} are trusted.`;
      }
    } catch (cause) {
      keyPreview = null;
      retryConnectionAlias = null;
      error = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  function closeKeyPreview() {
    if (activeAction !== null) return;
    keyPreview = null;
    keyPreviewMessage = null;
    retryConnectionAlias = null;
    error = null;
    success = null;
  }

  async function recheckHostKey() {
    if (!keyPreview || activeAction !== null) return;
    const requestedHost = keyPreview.requestedHost;
    activeAction = `preview_host_key:${requestedHost}`;
    keyPreviewMessage = null;
    error = null;
    success = null;
    try {
      keyPreview = await loadHostKeyPreview(requestedHost);
      if (!keyPreview) {
        retryConnectionAlias = null;
        success = `All host keys for ${requestedHost} are trusted.`;
      }
    } catch (cause) {
      keyPreviewMessage = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  async function copyFingerprint() {
    if (!keyPreview || activeAction !== null) return;
    try {
      await navigator.clipboard.writeText(keyPreview.fingerprint);
      keyPreviewMessage = 'New fingerprint copied.';
    } catch (cause) {
      keyPreviewMessage = `Could not copy fingerprint: ${errorMessage(cause)}`;
    }
  }

  async function applyHostKeyAction() {
    if (!keyPreview || !keyPreview.replaceable || activeAction !== null) return;
    const trustedHost = keyPreview.host;
    const requestedHost = keyPreview.requestedHost;
    const action = keyPreview.state === 'new' ? 'add' : 'replace';
    activeAction = `trust_host_key:${trustedHost}`;
    error = null;
    success = null;
    keyPreviewMessage = null;
    try {
      const result = await invoke<HostKeyActionResult>('trust_host_key', {
        preview: keyPreview,
        action,
      });
      keyPreview = result.preview;
      if (result.refreshed) {
        keyPreviewMessage = result.preview
          ? 'The remote key changed while this dialog was open. Review the refreshed details.'
          : 'The stored host-key state changed; all keys are trusted now.';
        retryConnectionAlias = result.preview ? retryConnectionAlias : null;
      } else if (!result.preview) {
        const retryAlias = retryConnectionAlias;
        retryConnectionAlias = null;
        if (retryAlias) {
          activeAction = `test_host_connection:${retryAlias}`;
          success = await invoke<string>('test_host_connection', { alias: retryAlias });
        } else {
          success = `All host keys for ${requestedHost} are trusted.`;
        }
      }
    } catch (cause) {
      keyPreviewMessage = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  async function testHostConnection(host: HostSummary) {
    if (activeAction !== null) return;
    await previewHostKey(host, true);
    if (keyPreview || error) return;
    activeAction = `test_host_connection:${host.alias}`;
    try {
      success = await invoke<string>('test_host_connection', { alias: host.alias });
    } catch (cause) {
      error = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  function endpoint(host: HostSummary): string {
    if (host.port === null) return host.hostname;
    return host.hostname.includes(':')
      ? `[${host.hostname}]:${host.port}`
      : `${host.hostname}:${host.port}`;
  }

  function authLabel(auth: HostSummary['auth']): string {
    return auth === 'agent' ? 'SSH agent' : auth === 'password' ? 'Password' : 'Key file';
  }

  function routeLabel(route: HostSummary['route']): string {
    if (route.type === 'managed_host') return `Via ${route.alias}`;
    if (route.type === 'proxy_jump') return `ProxyJump ${route.spec}`;
    return 'Direct';
  }
</script>

<section class="hosts-page" aria-labelledby="hosts-heading">
  <div class="hosts-toolbar">
    <div>
      <p class="section-kicker">Vault inventory</p>
      <h2 id="hosts-heading">SSH hosts</h2>
      <p>Vault-backed connection profiles available to approved sessions.</p>
    </div>
    <div class="toolbar-actions">
      {#if hosts !== null}
        <span class="unlock-status" aria-live="off">
          <ShieldCheck size={15} />
          <span>{unlockMethodLabel()}</span>
          <strong>{formatCountdown(unlock.idleRemainingSecs)}</strong>
        </span>
        <button
          class="icon-button"
          onclick={loadHosts}
          disabled={activeAction !== null}
          aria-label="Refresh hosts"
          title="Refresh hosts"
        >
          <RefreshCw size={17} class={activeAction === 'list_hosts' ? 'spin' : undefined} />
        </button>
        <button
          class="icon-button"
          onclick={lockHosts}
          disabled={activeAction !== null}
          aria-label="Lock host list"
          title="Lock host list"
        >
          <LockKeyhole size={17} />
        </button>
      {/if}
      <button
        class="primary-button"
        onclick={openAdd}
        disabled={Boolean(blocker) || hosts === null || activeAction !== null}
        title={blocker ?? (hosts === null ? 'Unlock the host list first.' : undefined)}
      >
        <Plus size={16} /> Add host
      </button>
    </div>
  </div>

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

  {#if blocker}
    <div class="host-gate" in:fade={{ duration: enterDuration }}>
      <div class="host-gate-mark"><LockKeyhole size={22} /></div>
      <div>
        <h3>Host management unavailable</h3>
        <p>{blocker}</p>
      </div>
      {#if snapshot && !snapshot.vaultExists}
        <button class="secondary-button" onclick={onSetup}>Open setup</button>
      {/if}
    </div>
  {:else if unlock.state === 'locked' || hosts === null}
    <div class="host-gate" in:fade={{ duration: enterDuration }}>
      <div class="host-gate-mark"><KeyRound size={22} /></div>
      <div>
        <h3>Credential vault locked</h3>
        <p>Unlock once to manage hosts. It locks after {unlock.idleTimeoutMinutes} minutes of inactivity.</p>
      </div>
      <div class="unlock-actions" aria-label="Unlock methods">
        {#if snapshot?.touchIdEnrolled}
          <button class="primary-button" onclick={() => unlockHosts('unlock_vault_with_touch_id')} disabled={activeAction !== null}>
            <Fingerprint size={16} /> {activeAction === 'unlock_vault_with_touch_id' ? 'Unlocking...' : 'Touch ID'}
          </button>
        {/if}
        {#if snapshot?.pin.state === 'ready'}
          <button class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_pin')} disabled={activeAction !== null}>
            <KeyRound size={16} /> {activeAction === 'unlock_vault_with_pin' ? 'Unlocking...' : 'Sloosh PIN'}
          </button>
        {/if}
        <button class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_master')} disabled={activeAction !== null}>
          <LockKeyhole size={16} /> {activeAction === 'unlock_vault_with_master' ? 'Unlocking...' : 'Master Password'}
        </button>
      </div>
    </div>
  {:else if hosts.length === 0}
    <div class="host-empty" in:fade={{ duration: enterDuration }}>
      <Server size={24} />
      <h3>No vault-backed hosts</h3>
      <p>Add the first connection profile for approved SSH work.</p>
      <button class="primary-button" onclick={openAdd}><Plus size={16} /> Add host</button>
    </div>
  {:else}
    <ul class="host-list" aria-label="Vault-backed SSH hosts">
      {#each hosts as host (host.alias)}
        <li
          animate:flip={{ duration: reducedMotion ? 0 : 160 }}
          in:fade={{ duration: enterDuration }}
          out:fade={{ duration: exitDuration }}
        >
          <div class="host-identity">
            <span class="host-icon"><Server size={18} /></span>
            <span><strong>{host.alias}</strong><small>{endpoint(host)}</small></span>
          </div>
          <dl class="host-meta">
            <div><dt>Auth</dt><dd>{authLabel(host.auth)}</dd></div>
            <div><dt>Route</dt><dd title={routeLabel(host.route)}>{routeLabel(host.route)}</dd></div>
          </dl>
          <div class="host-actions">
            <button
              class="icon-button"
              onclick={() => void previewHostKey(host)}
              disabled={activeAction !== null}
              aria-label={`Trust host key for ${host.alias}`}
              title={`Inspect and trust host key for ${host.alias}`}
            ><Fingerprint size={16} /></button>
            <button
              class="icon-button"
              onclick={() => void testHostConnection(host)}
              disabled={activeAction !== null}
              aria-label={`Test connection to ${host.alias}`}
              title={`Test SSH connection to ${host.alias}`}
            ><Cable size={16} /></button>
            <button
              class="icon-button"
              onclick={() => openEdit(host)}
              disabled={activeAction !== null}
              aria-label={`Edit ${host.alias}`}
              title={`Edit ${host.alias}`}
            ><Pencil size={16} /></button>
            <button
              class="icon-button danger-button"
              onclick={() => openDelete(host)}
              disabled={activeAction !== null}
              aria-label={`Remove ${host.alias}`}
              title={`Remove ${host.alias}`}
            ><Trash2 size={16} /></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

{#if mode === 'add' || mode === 'edit'}
    <dialog
      use:modal
      class="host-dialog"
      aria-modal="true"
      aria-labelledby="host-dialog-title"
      in:scale={{ start: reducedMotion ? 1 : 0.985, duration: enterDuration, opacity: 0 }}
      out:fade={{ duration: exitDuration }}
    >
      <form onsubmit={(event) => { event.preventDefault(); void saveHost(); }}>
        <header>
          <button
            type="button"
            class="icon-button dialog-close"
            onclick={closeDialog}
            disabled={activeAction !== null}
            aria-label="Close"
            title="Close"
          ><X size={17} /></button>
          <div>
            <p class="section-kicker">{mode === 'edit' ? 'Vault update' : 'New connection'}</p>
            <h2 id="host-dialog-title">{mode === 'edit' ? `Edit ${selected?.alias}` : 'Add SSH host'}</h2>
          </div>
        </header>

        <div class="host-form-sections">
          <fieldset class="form-section">
            <legend><Cable size={15} /> Connection</legend>
            <div class="host-form-grid">
              <label class="field-wide">
                <span>Alias</span>
                <input bind:value={form.alias} disabled={mode === 'edit'} required autocomplete="off" placeholder="production-api" />
              </label>
              <label class="field-wide">
                <span>Hostname</span>
                <input bind:value={form.hostname} required autocomplete="off" placeholder="server.example.com" />
              </label>
              <label>
                <span>User</span>
                <input bind:value={form.user} autocomplete="off" placeholder="System default" />
              </label>
              <label>
                <span>Port</span>
                <input bind:value={form.port} type="number" min="1" max="65535" inputmode="numeric" placeholder="22" />
              </label>
            </div>
          </fieldset>

          <fieldset class="form-section">
            <legend><ShieldCheck size={15} /> Authentication</legend>
            {#if mode === 'edit'}
              <label class="change-toggle">
                <input bind:checked={form.changeAuth} type="checkbox" />
                <span>Change authentication method</span>
                <small>Currently {authLabel(selected?.auth ?? form.auth)}</small>
              </label>
            {/if}
            {#if mode === 'add' || form.changeAuth}
              <div class="choice-grid auth-choices" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                <label class:chosen={form.auth === 'agent'}>
                  <input bind:group={form.auth} type="radio" value="agent" />
                  <KeyRound size={18} />
                  <span><strong>SSH agent</strong><small>Uses keys already loaded in the system SSH Agent. Sloosh stores no private key.</small></span>
                </label>
                <label class:chosen={form.auth === 'password'}>
                  <input bind:group={form.auth} type="radio" value="password" />
                  <ShieldCheck size={18} />
                  <span><strong>Password</strong><small>Stored encrypted in the Sloosh vault.</small></span>
                </label>
                <label class:chosen={form.auth === 'key_file'}>
                  <input bind:group={form.auth} type="radio" value="key_file" />
                  <FileKey2 size={18} />
                  <span><strong>Key file</strong><small>References an unencrypted Ed25519/ECDSA key. Load RSA or encrypted keys into SSH Agent.</small></span>
                </label>
              </div>
              {#if form.auth === 'agent'}
                <p class="auth-guidance" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}><Check size={15} /> Choose this when macOS Keychain or <code>ssh-add</code> already loaded your key.</p>
              {:else if form.auth === 'password'}
                <label class="conditional-field" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                  <span>SSH password</span>
                  <input bind:value={form.password} type="password" autocomplete="current-password" placeholder="Password for this SSH account" />
                  <small>Encrypted in the Sloosh vault. Cleared from this form immediately after submission.</small>
                </label>
              {:else if form.auth === 'key_file'}
                <label class="conditional-field" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                  <span>Private key file</span>
                  <div class="file-picker-row">
                    <input bind:value={form.keyFile} autocomplete="off" placeholder="/Users/name/.ssh/id_ed25519" aria-label="Private key file path" />
                    <button type="button" class="secondary-button" onclick={() => void chooseKeyFile()} disabled={activeAction !== null}>
                      <FolderOpen size={15} /> Choose…
                    </button>
                  </div>
                  <small>Type a full path when Finder hides <code>.ssh</code>, or choose a file. For encrypted keys, use SSH agent.</small>
                </label>
              {/if}
            {/if}
          </fieldset>

          <fieldset class="form-section">
            <legend><GitBranch size={15} /> Route</legend>
            <div class="route-choices">
              <label class:chosen={form.routeMode === 'direct'}>
                <input bind:group={form.routeMode} type="radio" value="direct" />
                <span><strong>Direct</strong><small>Connect to the host without a jump.</small></span>
              </label>
              <label class:chosen={form.routeMode === 'managed_host'}>
                <input bind:group={form.routeMode} type="radio" value="managed_host" />
                <span><strong>Through managed host</strong><small>Reuse another Sloosh host profile.</small></span>
              </label>
              <label class:chosen={form.routeMode === 'proxy_jump'}>
                <input bind:group={form.routeMode} type="radio" value="proxy_jump" />
                <span><strong>Advanced ProxyJump</strong><small>Use raw OpenSSH jump syntax.</small></span>
              </label>
            </div>
            {#if form.routeMode === 'managed_host'}
              <label class="conditional-field" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                <span>Managed host</span>
                <select bind:value={form.managedHost} required>
                  <option value="" disabled>Select a host profile</option>
                  {#each (hosts ?? []).filter((host) => host.alias !== form.alias) as host}
                    <option value={host.alias}>{host.alias} · {endpoint(host)}</option>
                  {/each}
                </select>
              </label>
            {:else if form.routeMode === 'proxy_jump'}
              <label class="conditional-field" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                <span>ProxyJump specification</span>
                <input bind:value={form.proxyJump} autocomplete="off" placeholder="user@bastion:22,edge" />
                <small>Comma-separated OpenSSH syntax. Cycles and routes over 8 hops are rejected.</small>
              </label>
            {/if}
            <div class="route-preview" aria-live="polite">
              <span>Route preview</span>
              <strong>{form.alias.trim() || 'This host'} ← {form.routeMode === 'direct' ? 'Direct' : form.routeMode === 'managed_host' ? (form.managedHost || 'Select host') : (form.proxyJump || 'Enter ProxyJump')}</strong>
            </div>
          </fieldset>
        </div>

        {#if formError}<p class="dialog-error" role="alert">{formError}</p>{/if}
        <footer>
          <button type="button" class="secondary-button" onclick={closeDialog} disabled={activeAction !== null}>Cancel</button>
          <button type="submit" class="primary-button" disabled={activeAction !== null}>
            {activeAction ? 'Authorizing...' : mode === 'edit' ? 'Save changes' : 'Add host'}
          </button>
        </footer>
      </form>
    </dialog>
{/if}

{#if keyPreview}
    <dialog
      use:modal
      class="host-dialog confirm-dialog host-key-dialog"
      aria-modal="true"
      aria-labelledby="trust-host-key-title"
      aria-describedby="trust-host-key-description trust-host-key-boundary"
      oncancel={(event) => {
        event.preventDefault();
        closeKeyPreview();
      }}
      in:scale={{ start: reducedMotion ? 1 : 0.985, duration: enterDuration, opacity: 0 }}
      out:fade={{ duration: exitDuration }}
    >
      <header>
        <button
          type="button"
          class="icon-button dialog-close"
          onclick={closeKeyPreview}
          disabled={activeAction !== null}
          aria-label="Close"
          title="Close"
        ><X size={17} /></button>
        <div>
          <p class="section-kicker">
            {keyPreview.state === 'new' ? 'Untrusted remote key' : 'Remote key changed'}
          </p>
          <h2 id="trust-host-key-title">
            {keyPreview.state === 'new' ? `Trust ${keyPreview.host}?` : `Review ${keyPreview.host}`}
          </h2>
        </div>
      </header>
      <p id="trust-host-key-description">
        {#if keyPreview.state === 'new'}
          Sloosh has not trusted this endpoint yet. Compare the fingerprint with a trusted,
          independent source before adding it.
        {:else}
          The endpoint presented a different key. Verify why it changed through an independent
          channel before replacing anything.
        {/if}
      </p>
      <dl class="host-key-details">
        <div><dt>Requested host</dt><dd>{keyPreview.requestedHost}</dd></div>
        <div><dt>Key belongs to</dt><dd>{keyPreview.host}</dd></div>
        <div><dt>Endpoint</dt><dd>{keyPreview.hostname.includes(':') ? `[${keyPreview.hostname}]:${keyPreview.port}` : `${keyPreview.hostname}:${keyPreview.port}`}</dd></div>
        <div><dt>Algorithm</dt><dd><code>{keyPreview.algorithm}</code></dd></div>
        {#if keyPreview.storedFingerprint}
          <div><dt>Stored fingerprint</dt><dd><code>{keyPreview.storedFingerprint}</code></dd></div>
        {/if}
        <div><dt>New fingerprint</dt><dd><code>{keyPreview.fingerprint}</code></dd></div>
        {#if keyPreview.source}
          <div>
            <dt>Stored in</dt>
            <dd><code>{keyPreview.source === 'sloosh' ? '~/.sloosh/known_hosts' : '~/.ssh/known_hosts'}</code></dd>
          </div>
        {/if}
      </dl>
      <p class="trust-boundary" id="trust-host-key-boundary">
        {#if keyPreview.state === 'external_mismatch'}
          This conflict comes from <code>~/.ssh/known_hosts</code>. Sloosh will not modify it;
          resolve that entry manually, then recheck.
        {:else if keyPreview.state === 'changed' && !keyPreview.replaceable}
          This Sloosh entry is not a single replaceable host line. Update it manually, then recheck.
        {:else}
          Sloosh re-resolves and re-probes immediately before changing only
          <code>~/.sloosh/known_hosts</code>.
        {/if}
      </p>
      {#if keyPreviewMessage}<p class="dialog-status" role="status">{keyPreviewMessage}</p>{/if}
      <footer>
        <button class="secondary-button" onclick={closeKeyPreview} disabled={activeAction !== null}>Cancel</button>
        <button class="secondary-button" onclick={() => void copyFingerprint()} disabled={activeAction !== null}>
          <Copy size={15} /> {keyPreview.state === 'new' ? 'Copy fingerprint' : 'Copy new'}
        </button>
        <button class="secondary-button" onclick={() => void recheckHostKey()} disabled={activeAction !== null}>
          <RefreshCw size={15} /> Recheck
        </button>
        {#if keyPreview.replaceable}
        <button
          class:destructive={keyPreview.state === 'changed'}
          class="primary-button"
          onclick={() => void applyHostKeyAction()}
          disabled={activeAction !== null}
        >
          {activeAction?.startsWith('trust_host_key:')
            ? 'Verifying again...'
            : keyPreview.state === 'new'
              ? 'Trust and retry'
              : 'Replace + retry'}
        </button>
        {/if}
      </footer>
    </dialog>
{/if}

{#if mode === 'delete' && selected}
    <dialog
      use:modal
      class="host-dialog confirm-dialog"
      aria-modal="true"
      aria-labelledby="remove-host-title"
      in:scale={{ start: reducedMotion ? 1 : 0.985, duration: enterDuration, opacity: 0 }}
      out:fade={{ duration: exitDuration }}
    >
      <header>
        <div>
          <p class="section-kicker">Vault update</p>
          <h2 id="remove-host-title">Remove {selected.alias}?</h2>
        </div>
      </header>
      {#if dependentHosts.length > 0}
        <p class="dependency-warning">Route used by {dependentHosts.map((host) => host.alias).join(', ')}. Change those hosts to another route before removing this profile.</p>
      {:else}
        <p>Removes its stored connection profile. Existing SSH sessions remain open until closed.</p>
      {/if}
      {#if formError}<p class="dialog-error" role="alert">{formError}</p>{/if}
      <footer>
        <button class="secondary-button" onclick={closeDialog} disabled={activeAction !== null}>Cancel</button>
        <button class="primary-button destructive" onclick={removeHost} disabled={activeAction !== null || dependentHosts.length > 0}>
          {activeAction === 'remove_host' ? 'Removing...' : 'Remove host'}
        </button>
      </footer>
    </dialog>
{/if}
