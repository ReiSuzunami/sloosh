const NATIVE_UNLOCK_ACTIONS = new Set([
  'unlock_vault_with_master',
  'unlock_vault_with_pin',
  'unlock_vault_with_touch_id',
]);

export function canStartVaultUnlockStatusSync(
  statusInFlight: boolean,
  activeAction: string | null,
): boolean {
  return !statusInFlight && !NATIVE_UNLOCK_ACTIONS.has(activeAction ?? '');
}
