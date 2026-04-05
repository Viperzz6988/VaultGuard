function getInvoke() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (typeof invoke !== "function") {
    throw new Error("VaultGuard could not open the system file dialog.");
  }

  return invoke;
}

async function dialogCommand(command, options = {}) {
  return getInvoke()(command, { options });
}

export async function open(options = {}) {
  return dialogCommand("dialog_open_file", options);
}

export async function save(options = {}) {
  return dialogCommand("dialog_save_file", options);
}
