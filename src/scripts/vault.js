const invoke = window.__TAURI__.core.invoke;
let sessionToken = null;

function normalizeInvokeError(error) {
  if (typeof error === "string") {
    return { message: error, code: null, data: null };
  }

  if (error && typeof error === "object") {
    if (typeof error.message === "string") {
      return { message: error.message, code: error.code || null, data: error };
    }

    const [variant, value] = Object.entries(error)[0] || [];
    if (variant === "BruteForceLockedOut" && value?.message) {
      return { message: value.message, code: variant, data: value };
    }
    if (typeof value === "string") {
      return { message: value, code: variant || null, data: value };
    }
    if (value && typeof value === "object" && typeof value.message === "string") {
      return { message: value.message, code: variant || null, data: value };
    }
  }

  return { message: "Unexpected error", code: null, data: null };
}

async function command(name, payload = {}) {
  try {
    return await invoke(name, payload);
  } catch (error) {
    const normalized = normalizeInvokeError(error);
    const wrapped = new Error(normalized.message);
    wrapped.code = normalized.code;
    wrapped.data = normalized.data;
    throw wrapped;
  }
}

function requireSession(payload = {}) {
  if (!sessionToken) {
    throw new Error("Authorization required");
  }
  return { ...payload, sessionToken };
}

export const vaultApi = {
  checkVaultExists: () => command("check_vault_exists"),
  checkVaultUnlocked: () => command("check_vault_unlocked"),
  createVault: async (password) => {
    const response = await command("create_vault", { password });
    sessionToken = response.session_token;
    return response;
  },
  unlockVault: async (password) => {
    const response = await command("unlock_vault", { password });
    sessionToken = response.session_token;
    return response;
  },
  lockVault: async () => {
    try {
      return await command("lock_vault");
    } finally {
      sessionToken = null;
    }
  },
  getBruteForceStatus: () => command("get_brute_force_status"),
  getVaultFileStatus: () => command("get_vault_file_status"),
  getEntries: () => command("get_entries"),
  getEntry: (id) => command("get_entry", requireSession({ id })),
  createEntry: (input) => command("create_entry", requireSession({ input })),
  updateEntry: (id, input) => command("update_entry", requireSession({ id, input })),
  reorderEntries: (entryId, newSortOrder, newCategoryId) =>
    command(
      "reorder_entries",
      requireSession({ entryId, newSortOrder, newCategoryId })
    ),
  moveEntryToCategory: (entryId, categoryId) =>
    command("move_entry_to_category", requireSession({ entryId, categoryId })),
  reorderEntry: (entryId, targetEntryId, position) =>
    command("reorder_entry", requireSession({ entryId, targetEntryId, position })),
  deleteEntry: (id) => command("delete_entry", requireSession({ id })),
  restoreEntry: (id) => command("restore_entry", requireSession({ id })),
  permanentDelete: (id) => command("permanent_delete", requireSession({ id })),
  getTrash: () => command("get_trash", requireSession()),
  getCategories: () => command("get_categories"),
  createCategory: (input) => command("create_category", requireSession({ input })),
  updateCategory: (id, input) => command("update_category", requireSession({ id, input })),
  reorderCategories: (orderedIds) => command("reorder_categories", requireSession({ orderedIds })),
  deleteCategory: (id) => command("delete_category", requireSession({ id })),
  generatePassword: (options) => command("generate_password", { options }),
  generatePassphrase: (wordCount, separator) =>
    command("generate_passphrase", { wordCount, separator }),
  checkPasswordStrength: (password) => command("check_password_strength", { password }),
  copyToClipboard: (text, entryId = null) => command("copy_to_clipboard", requireSession({ text, entryId })),
  scheduleClipboardClear: (timeoutSecs = 300) =>
    command("schedule_clipboard_clear", requireSession({ timeoutSecs })),
  clearClipboard: () => command("clear_clipboard"),
  openUrl: (url) => command("open_url", requireSession({ url })),
  getSettings: () => command("get_settings"),
  updateSettings: (input) => command("update_settings", requireSession({ input })),
  changeMasterPassword: (currentPassword, newPassword) =>
    command("change_master_password", requireSession({ currentPassword, newPassword })),
  exportVaultJson: (password) => command("export_vault_json", requireSession({ password })),
  exportKeepassXml: (password) => command("export_keepass_xml", requireSession({ password })),
  exportBackup: () => command("export_backup", requireSession()),
  restoreLastGoodBackup: (password) => command("restore_last_good_backup", { password }),
  importBitwardenJson: (password, jsonContent) =>
    command("import_bitwarden_json", requireSession({ password, jsonContent })),
  importCsv: (password, csvContent) =>
    command("import_csv", requireSession({ password, csvContent })),
  importKeepassXml: (password, xmlContent) =>
    command("import_keepass_xml", requireSession({ password, xmlContent })),
  clearSession: () => {
    sessionToken = null;
  }
};
