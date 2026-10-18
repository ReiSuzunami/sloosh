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
  let warning = $state<string | null>(null);
  const hostSources = ['ssh_config', 'vault'] as const;
  let hostSource = $state<HostSummary['source']>('ssh_config');
  let formError = $state<string | null>(null);
  let form = $state<HostForm>(emptyHostForm());
  let keyPreview = $state<HostKeyPreview | null>(null);
  let keyPreviewMessage = $state<string | null>(null);
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

  const sourceHosts = $derived((hosts ?? []).filter((host) => host.source === hostSource));
  const systemHostCount = $derived((hosts ?? []).filter((host) => host.source === 'ssh_config').length);
  const vaultHostCount = $derived((hosts ?? []).filter((host) => host.source === 'vault').length);

  const blocker = $derived(
    !snapshot
      ? 'Local status is unavailable.'
      : null,
  );

  function sourceLabel(source: HostSummary['source']): string {
    return source === 'ssh_config' ? 'System SSH config' : 'Sloosh vault';
  }

  function jumpChoices(): HostSummary[] {
    return (hosts ?? []).filter((host) => host.source === form.source && host.alias !== form.alias);
  }

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
    void loadHosts();
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
    if (next.state === 'locked' && !wasLocked) {
      hostOperationGeneration += 1;
      hosts = hosts?.filter((host) => host.source === 'ssh_config') ?? null;
      form.password = '';
      form.privateKey = '';
      mode = null;
      selected = null;
      formError = null;
      keyPreview = null;
      keyPreviewMessage = null;
    } else if (wasLocked && next.state === 'unlocked' && activeAction === null) {
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
    if (activeAction !== null) return;
    activeAction = 'list_hosts';
    const operation = ++hostOperationGeneration;
    error = null;
    success = null;
    warning = null;
    try {
      const nextHosts = await invoke<HostSummary[]>('list_hosts');
      if (operation === hostOperationGeneration) {
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
    warning = null;
    formError = null;
    try {
      const next = await invoke<VaultUnlockSnapshot>(command);
      if (generation !== unlockGeneration) return;
      setUnlock(next);
      const nextHosts = await invoke<HostSummary[]>('list_hosts');
      if (operation === hostOperationGeneration) {
        hosts = nextHosts;
        success = 'Vault unlocked.';
      }
    } catch (cause) {
      if (mode === 'add' || mode === 'edit') formError = errorMessage(cause);
      else error = errorMessage(cause);
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
    warning = null;
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

  function chooseSource(source: HostSummary['source']) {
    form.source = source;
    form.managedHost = '';
    form.auth = source === 'ssh_config' ? 'agent' : 'password';
    form.password = '';
    form.privateKey = '';
    form.keyFile = '';
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
    form.privateKey = '';
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
    if (form.source === 'vault' && unlock.state !== 'unlocked') {
      formError = 'Unlock the vault below Save to before saving.';
      return;
    }
    let submission;
    try {
      submission = buildHostSubmission(form, mode, hosts ?? []);
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
    warning = null;
    form.password = '';
    form.privateKey = '';
    try {
      const agentWarning = await invoke<string | null>(command, {
        host: commandHost,
        ...(command === 'update_host' ? { changeAuth } : {}),
      });
      if (operation === hostOperationGeneration && (unlock.state === 'unlocked' || host.source === 'ssh_config')) {
        hosts = command === 'update_host'
          ? (hosts ?? []).map((entry) => entry.alias === host.alias ? host : entry)
          : [...(hosts ?? []), host].sort((left, right) => left.alias.localeCompare(right.alias));
        success = command === 'update_host' ? `Updated ${host.alias}.` : `Added ${host.alias}.`;
        if (agentWarning) { success = null; warning = agentWarning; }
        hostSource = host.source;
        mode = null;
        selected = null;
      }
    } catch (cause) {
      formError = errorMessage(cause);
    } finally {
      commandHost.password = null;
      commandHost.privateKey = null;
      activeAction = null;
    }
  }

  async function removeHost() {
    if (!selected || activeAction !== null) return;
    const alias = selected.alias;
    const source = selected.source;
    activeAction = 'remove_host';
    const operation = ++hostOperationGeneration;
    formError = null;
    error = null;
    success = null;
    warning = null;
    try {
      await invoke<void>('remove_host', { alias, source });
      if (operation === hostOperationGeneration && (unlock.state === 'unlocked' || source === 'ssh_config')) {
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

  async function testHostConnection(host: HostSummary) {
    if (activeAction !== null) return;
    activeAction = `preview_host_key:${host.alias}`;
    error = null;
    success = null;
    warning = null;
    keyPreviewMessage = null;
    try {
      const preview = await loadHostKeyPreview(host.alias);
      if (preview) {
        keyPreview = preview;
      } else {
        keyPreview = null;
        activeAction = `test_host_connection:${host.alias}`;
        success = await invoke<string>('test_host_connection', { alias: host.alias });
      }
    } catch (cause) {
      keyPreview = null;
      error = errorMessage(cause);
    } finally {
      activeAction = null;
    }
  }

  function closeKeyPreview() {
    if (activeAction !== null) return;
    keyPreview = null;
    keyPreviewMessage = null;
    error = null;
    success = null;
    warning = null;
  }

  async function recheckHostKey() {
    if (!keyPreview || activeAction !== null) return;
    const requestedHost = keyPreview.requestedHost;
    activeAction = `preview_host_key:${requestedHost}`;
    keyPreviewMessage = null;
    error = null;
    success = null;
    warning = null;
    try {
      keyPreview = await loadHostKeyPreview(requestedHost);
      if (!keyPreview) {
        activeAction = `test_host_connection:${requestedHost}`;
        success = await invoke<string>('test_host_connection', { alias: requestedHost });
      }
    } catch (cause) {
      if (keyPreview) keyPreviewMessage = errorMessage(cause);
      else error = errorMessage(cause);
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
    warning = null;
    keyPreviewMessage = null;
    try {
      const result = await invoke<HostKeyActionResult>('trust_host_key', {
        preview: keyPreview,
        action,
      });
      keyPreview = result.preview;
      if (!result.preview) {
        activeAction = `test_host_connection:${requestedHost}`;
        success = await invoke<string>('test_host_connection', { alias: requestedHost });
      } else if (result.refreshed) {
        keyPreviewMessage = 'The remote key changed while this dialog was open. Review the refreshed details.';
      }
    } catch (cause) {
      if (keyPreview) keyPreviewMessage = errorMessage(cause);
      else error = errorMessage(cause);
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
    return auth === 'agent' ? 'SSH agent' : auth === 'password' ? 'Password' : auth === 'private_key' ? 'Private key' : 'Key file';
  }

  function routeLabel(route: HostSummary['route']): string {
    if (route.type === 'managed_host') return `Via ${route.alias}`;
    if (route.type === 'proxy_jump') return `ProxyJump ${route.spec}`;
    return 'Direct';
  }
</script>

<section class="hosts-page" aria-labelledby="hosts-heading">
  <div class="hosts-toolbar">
    <h1 id="hosts-heading">Hosts</h1>
    <div class="toolbar-actions">
      <button class="icon-button" onclick={loadHosts} disabled={activeAction !== null} aria-label="Refresh hosts" title="Refresh hosts"><RefreshCw size={17} /></button>
      <button class="primary-button" onclick={openAdd} disabled={Boolean(blocker) || hosts === null || activeAction !== null}><Plus size={16} /> Add host</button>
    </div>
  </div>
  {#if error || warning || success}
    <div class="notice" class:error={Boolean(error)} class:warning={!error && Boolean(warning)} class:success={!error && !warning} role={error ? 'alert' : 'status'}>
      {#if error || warning}<CircleAlert size={18} />{:else}<Check size={18} />{/if}
      <span>{error ?? warning ?? success}</span>
    </div>
  {/if}
  {#if blocker}
    <p class="constraint">{blocker}</p>
  {:else if hosts !== null}
    <div class="seg-choices host-source-switch" role="radiogroup" aria-label="Host source">
      {#each hostSources as source}
        <label class:chosen={hostSource === source}>
          <input bind:group={hostSource} type="radio" name="host-list-source" value={source} />
          <span>{sourceLabel(source)}</span>
          {#if source === 'ssh_config' || unlock.state === 'unlocked'}
            <span class="host-source-count">{source === 'ssh_config' ? systemHostCount : vaultHostCount}</span>
          {:else}
            <span class="host-source-count" title="Locked"><LockKeyhole size={11} /><span class="sr-only">locked</span></span>
          {/if}
        </label>
      {/each}
    </div>
    {#key hostSource}
      <section class="host-source-group" aria-label={sourceLabel(hostSource)}>
        <header class="host-source-header">
          <div>
            <h3>{sourceLabel(hostSource)}</h3>
            <p>{hostSource === 'ssh_config' ? '~/.ssh/config · keys stay in your SSH Agent' : unlock.state === 'locked' ? 'Locked · private credentials' : 'Unlocked · private credentials'}</p>
          </div>
          {#if hostSource === 'vault'}
            <div class="unlock-actions">
              {#if unlock.state === 'unlocked'}
                <span class="unlock-status">{unlockMethodLabel()} · {formatCountdown(unlock.idleRemainingSecs)}</span>
                <button class="icon-button" onclick={lockHosts} disabled={activeAction !== null} aria-label="Lock vault" title="Lock vault"><LockKeyhole size={16} /></button>
              {:else if snapshot?.vaultExists && snapshot?.nativeApprovalAvailable}
                {#if snapshot.touchIdEnrolled}<button class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_touch_id')} disabled={activeAction !== null}><Fingerprint size={15} /> Touch ID</button>{/if}
                {#if snapshot.pin.state === 'ready'}<button class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_pin')} disabled={activeAction !== null}>PIN</button>{/if}
                <button class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_master')} disabled={activeAction !== null}>Master password</button>
              {:else}
                <button class="secondary-button" onclick={onSetup}>Set up vault</button>
              {/if}
            </div>
          {/if}
        </header>
        {#if sourceHosts.length > 0}
    <ul class="host-list" aria-label={`${sourceLabel(hostSource)} hosts`}>
      {#each sourceHosts as host (host.alias)}
        <li
          animate:flip={{ duration: reducedMotion ? 0 : 160 }}
          in:fade={{ duration: enterDuration }}
          out:fade={{ duration: exitDuration }}
        >
          <div class="host-identity">
            <strong>{host.alias}</strong>
            <span class="host-endpoint" title={endpoint(host)}>{endpoint(host)}</span>
            {#if host.route.type !== 'direct'}
              <small class="host-route" title={routeLabel(host.route)}>{routeLabel(host.route)}</small>
            {/if}
          </div>
          <div class="host-tags">
            {#if host.source === 'vault'}<span class="host-tag">{authLabel(host.auth)}</span>{/if}
            {#if host.editError}<span class="host-tag muted" title={host.editError}>Read-only</span>{/if}
          </div>
          <div class="host-actions">
            <button
              class="secondary-button host-test"
              onclick={() => void testHostConnection(host)}
              disabled={activeAction !== null}
              aria-label={`Test connection to ${host.alias}`}
              title={`Test SSH connection to ${host.alias}`}
            ><Cable size={15} /> {activeAction?.endsWith(`:${host.alias}`) ? 'Testing…' : 'Test'}</button>
            <button
              class="icon-button"
              onclick={() => openEdit(host)}
              disabled={activeAction !== null || Boolean(host.editError)}
              aria-label={`Edit ${host.alias}`}
              title={host.editError ?? `Edit ${host.alias}`}
            ><Pencil size={16} /></button>
            <button
              class="icon-button danger-button"
              onclick={() => openDelete(host)}
              disabled={activeAction !== null || Boolean(host.editError)}
              aria-label={`Remove ${host.alias}`}
              title={host.editError ?? `Remove ${host.alias}`}
            ><Trash2 size={16} /></button>
          </div>
        </li>
      {/each}
    </ul>
        {:else if hostSource === 'ssh_config' || unlock.state === 'unlocked'}
          <p class="constraint">No hosts saved here.</p>
        {/if}
      </section>
    {/key}
  {/if}
</section>

{#if mode === 'add' || mode === 'edit'}
    <dialog
      use:modal
      class="host-dialog"
      aria-modal="true"
      aria-labelledby="host-dialog-title"
      onclose={closeDialog}
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
            <h2 id="host-dialog-title">{mode === 'edit' ? `Edit ${selected?.alias}` : 'Add SSH host'}</h2>
            {#if mode === 'edit'}
              <p class="dialog-subtitle">Saved in {form.source === 'ssh_config' ? '~/.ssh/config' : 'the Sloosh vault'} · source cannot change</p>
            {/if}
          </div>
        </header>

        <div class="host-form-sections compact">
          {#if mode === 'add'}
            <fieldset class="form-section">
              <legend>Save to</legend>
              <div class="seg-choices" role="radiogroup" aria-label="Save to">
                <label class:chosen={form.source === 'vault'}>
                  <input type="radio" name="host-source" checked={form.source === 'vault'} onchange={() => chooseSource('vault')} />
                  <span>Sloosh vault</span>
                </label>
                <label class:chosen={form.source === 'ssh_config'}>
                  <input type="radio" name="host-source" checked={form.source === 'ssh_config'} onchange={() => chooseSource('ssh_config')} />
                  <span>System SSH config</span>
                </label>
              </div>
              {#if form.source === 'ssh_config'}
                <p class="field-hint">~/.ssh/config and your SSH Agent. No vault copy.</p>
              {:else if unlock.state === 'unlocked'}
                <p class="field-hint">Private credentials encrypted by Sloosh · unlocked, {unlockMethodLabel()}</p>
              {:else}
                <div class="dialog-unlock-row" aria-label="Unlock vault for this host">
                  <p class="field-hint"><LockKeyhole size={13} /> Vault locked. Unlock to save; entered details stay here.</p>
                  {#if snapshot?.vaultExists && snapshot?.nativeApprovalAvailable}
                    <div class="unlock-actions">
                      {#if snapshot.touchIdEnrolled}
                        <button type="button" class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_touch_id')} disabled={activeAction !== null}><Fingerprint size={15} /> Touch ID</button>
                      {/if}
                      {#if snapshot.pin.state === 'ready'}
                        <button type="button" class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_pin')} disabled={activeAction !== null}>PIN</button>
                      {/if}
                      <button type="button" class="secondary-button" onclick={() => unlockHosts('unlock_vault_with_master')} disabled={activeAction !== null}>Master password</button>
                    </div>
                  {:else}
                    <button type="button" class="secondary-button" onclick={() => { closeDialog(); onSetup(); }}>Open vault setup</button>
                  {/if}
                </div>
                {#if formError}<p class="dialog-error" role="alert">{formError}</p>{/if}
              {/if}
            </fieldset>
          {/if}
          <fieldset class="form-section">
            <legend><Cable size={15} /> Connection</legend>
            <div class="host-form-grid compact">
              <label class="field-alias">
                <span>Alias</span>
                <input bind:value={form.alias} disabled={mode === 'edit'} required autocomplete="off" placeholder="production-api" />
              </label>
              <label class="field-host">
                <span>Hostname</span>
                <input bind:value={form.hostname} required autocomplete="off" placeholder="server.example.com" />
              </label>
              <label class="field-user">
                <span>User</span>
                <input bind:value={form.user} autocomplete="off" placeholder="System default" />
              </label>
              <label class="field-port">
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
                <span>Change authentication</span>
                <small>Currently {authLabel(selected?.auth ?? form.auth)}</small>
              </label>
            {/if}
            {#if mode === 'add' || form.changeAuth}
              <div class="seg-choices" role="radiogroup" aria-label="Authentication method" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                {#if form.source === 'ssh_config'}
                <label class:chosen={form.auth === 'agent'}>
                  <input bind:group={form.auth} type="radio" value="agent" />
                  <KeyRound size={14} /><span>SSH Agent</span>
                </label>
                {:else}
                <label class:chosen={form.auth === 'password'}>
                  <input bind:group={form.auth} type="radio" value="password" />
                  <ShieldCheck size={14} /><span>Password</span>
                </label>
                {/if}
                <label class:chosen={form.auth === 'key_file'}>
                  <input bind:group={form.auth} type="radio" value="key_file" />
                  <FileKey2 size={14} /><span>Key file</span>
                </label>
                <label class:chosen={form.auth === 'private_key'}>
                  <input bind:group={form.auth} type="radio" value="private_key" />
                  <FileKey2 size={14} /><span>Paste key</span>
                </label>
              </div>
              {#if form.auth === 'agent'}
                <p class="field-hint">Uses keys already loaded in your SSH Agent.</p>
              {:else if form.auth === 'password'}
                <label class="conditional-field" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                  <span>SSH password</span>
                  <input bind:value={form.password} type="password" autocomplete="current-password" placeholder="Password for this SSH account" />
                  <small>Stored encrypted in the Sloosh vault.</small>
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
                  <small>{form.source === 'ssh_config' ? 'Saving runs ssh-add once; Sloosh keeps no key. Reload after the agent restarts.' : 'The path is stored in the vault; the key stays on disk.'} RSA or encrypted keys also need the matching identity in the daemon's SSH Agent.</small>
                </label>
              {:else if form.auth === 'private_key'}
                <label class="conditional-field">
                  <span>Private key content</span>
                  <textarea bind:value={form.privateKey} rows="5" maxlength="262144" autocomplete="off" spellcheck="false" autocapitalize="off" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                  <small>{form.source === 'ssh_config' ? 'Loaded into SSH Agent once on save; Sloosh keeps no copy. Reload after the agent restarts.' : 'Stored encrypted in the vault, never written to a key file.'} RSA or encrypted keys also need the matching identity in the daemon's SSH Agent.</small>
                </label>
              {/if}
            {/if}
          </fieldset>

          <fieldset class="form-section">
            <legend><GitBranch size={15} /> Route</legend>
            {#if form.routeMode === 'proxy_jump'}
              <p class="field-hint">Existing ProxyJump: <code>{form.proxyJump}</code>. Preserved unless you choose a route below.</p>
            {/if}
            <div class="seg-choices" role="radiogroup" aria-label="Route">
              <label class:chosen={form.routeMode === 'direct'}>
                <input bind:group={form.routeMode} type="radio" value="direct" />
                <span>Direct</span>
              </label>
              <label class:chosen={form.routeMode === 'managed_host'}>
                <input bind:group={form.routeMode} type="radio" value="managed_host" />
                <span>Through saved host</span>
              </label>
            </div>
            {#if form.routeMode === 'managed_host'}
              <label class="conditional-field" in:fade={{ duration: enterDuration }} out:fade={{ duration: exitDuration }}>
                <span>Jump host</span>
                <select bind:value={form.managedHost} required>
                  <option value="" disabled>Select a saved host</option>
                  {#each jumpChoices() as host (host.alias)}
                    <option value={host.alias}>{host.alias} · {endpoint(host)}</option>
                  {/each}
                </select>
              </label>
            {/if}
          </fieldset>
        </div>

        {#if formError && !(mode === 'add' && form.source === 'vault' && unlock.state !== 'unlocked')}<p class="dialog-error" role="alert">{formError}</p>{/if}
        <footer>
          <button type="button" class="secondary-button" onclick={closeDialog} disabled={activeAction !== null}>Cancel</button>
          <button type="submit" class="primary-button" disabled={activeAction !== null || (form.source === 'vault' && unlock.state !== 'unlocked')}>
            {activeAction?.startsWith('unlock_vault') ? 'Unlocking...' : activeAction ? 'Saving...' : form.source === 'vault' && unlock.state !== 'unlocked' ? 'Unlock to save' : mode === 'edit' ? 'Save changes' : 'Add host'}
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
      <header class="dialog-header-end">
        <div>
          <h2 id="trust-host-key-title">
            {keyPreview.state === 'new' ? `Trust host key for ${keyPreview.host}?` : `Host key changed for ${keyPreview.host}`}
          </h2>
        </div>
        <button
          type="button"
          class="icon-button dialog-close"
          onclick={closeKeyPreview}
          disabled={activeAction !== null}
          aria-label="Close"
          title="Close"
        ><X size={17} /></button>
      </header>
      <p id="trust-host-key-description">
        {#if keyPreview.state === 'new'}
          Verify this fingerprint with an independent, trusted source.
        {:else}
          Verify this change independently before replacing the key.
        {/if}
      </p>
      <div class="fingerprint-block">
        {#if keyPreview.storedFingerprint}
          <div class="fingerprint-row">
            <span>Stored fingerprint</span>
            <code>{keyPreview.storedFingerprint}</code>
          </div>
        {/if}
        <div class="fingerprint-row">
          <span>{keyPreview.storedFingerprint ? 'New fingerprint' : 'Fingerprint'} · {keyPreview.algorithm}</span>
          <code>{keyPreview.fingerprint}</code>
          <button
            type="button"
            class="icon-button"
            onclick={() => void copyFingerprint()}
            disabled={activeAction !== null}
            aria-label={keyPreview.storedFingerprint ? 'Copy new fingerprint' : 'Copy fingerprint'}
            title={keyPreview.storedFingerprint ? 'Copy new fingerprint' : 'Copy fingerprint'}
          ><Copy size={15} /></button>
        </div>
      </div>
      <dl class="host-key-details">
        <div><dt>Requested host</dt><dd>{keyPreview.requestedHost}</dd></div>
        <div><dt>Key belongs to</dt><dd>{keyPreview.host}</dd></div>
        {#if keyPreview.hostKeyAlias}<div><dt>Host-key alias</dt><dd>{keyPreview.hostKeyAlias}</dd></div>{/if}
        <div><dt>Endpoint</dt><dd>{keyPreview.hostname.includes(':') ? `[${keyPreview.hostname}]:${keyPreview.port}` : `${keyPreview.hostname}:${keyPreview.port}`}</dd></div>
        {#if keyPreview.source}
          <div>
            <dt>Stored in</dt>
            <dd><code>{keyPreview.source === 'sloosh' ? '~/.sloosh/known_hosts' : '~/.ssh/known_hosts'}</code></dd>
          </div>
        {/if}
      </dl>
      <p class="trust-boundary" id="trust-host-key-boundary">
        {#if keyPreview.state === 'external_mismatch'}
          Edit <code>~/.ssh/known_hosts</code> manually, then recheck. Sloosh will not change it.
        {:else if keyPreview.state === 'changed' && !keyPreview.replaceable}
          This entry cannot be replaced here. Edit <code>~/.sloosh/known_hosts</code> manually, then recheck.
        {:else}
          Changes only <code>~/.sloosh/known_hosts</code>.
        {/if}
      </p>
      {#if keyPreviewMessage}<p class="dialog-status" role="status">{keyPreviewMessage}</p>{/if}
      <footer>
        <button class="secondary-button" onclick={closeKeyPreview} disabled={activeAction !== null}>Cancel</button>
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
            ? 'Verifying...'
            : keyPreview.state === 'new'
              ? 'Trust and continue'
              : 'Replace and continue'}
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
      onclose={closeDialog}
      in:scale={{ start: reducedMotion ? 1 : 0.985, duration: enterDuration, opacity: 0 }}
      out:fade={{ duration: exitDuration }}
    >
      <header>
        <div>
          <h2 id="remove-host-title">Remove {selected.alias}?</h2>
        </div>
      </header>
      {#if dependentHosts.length > 0}
        <p class="dependency-warning">Jump host for {dependentHosts.map((host) => host.alias).join(', ')}. Change their routes before removing it.</p>
      {:else}
        <p>{selected.source === 'ssh_config' ? 'Removes this Host block from ~/.ssh/config. Routes using this alias may stop working. Keys in SSH Agent are kept.' : 'Deletes this vault profile and its stored credential.'} Existing SSH sessions stay open.</p>
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

<style>
  .host-source-switch { margin-top: var(--space-xl); }
  .host-source-switch + .host-source-group { margin-top: var(--space-lg); }

  .host-source-count {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 1.25rem;
    height: 1.125rem;
    padding-inline: 0.3rem;
    color: var(--muted);
    font-size: 0.6875rem;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    line-height: 1;
    background: var(--sidebar);
    border-radius: 999px;
    transition: color 140ms var(--ease-out), background-color 140ms var(--ease-out);
  }

  .host-source-switch label.chosen .host-source-count {
    color: var(--brand-ink);
    background: color-mix(in oklch, var(--brand) 24%, transparent);
  }
</style>
