import {
  DEFAULT_GENERATOR_STATE,
  buildEntryPayload,
  draftFromEntry,
  emptyEntryDraft,
  normalizeGeneratorState
} from "/scripts/generator.js";
import { open, save } from "@tauri-apps/plugin-dialog";
import { formatDateTime, getLanguage, initI18n, setLanguage, t } from "/scripts/i18n.js";
import { collectTags, filterEntries } from "/scripts/search.js";
import {
  renderApp,
  renderDetailPanel,
  renderEntryList,
  renderToasts
} from "/scripts/ui.js";
import { vaultApi } from "/scripts/vault.js";

let root = null;
const CUSTOM_CATEGORY_COLORS = [
  "#7c6fe0",
  "#4ca8e0",
  "#60b87a",
  "#e0a24c",
  "#d96c6c",
  "#5fb8a6",
  "#8c7ae6",
  "#c27ae0"
];
const DEFAULT_CLIPBOARD_TIMEOUT_SECS = 300;
const CLIPBOARD_CHOICE_DISMISS_SECS = 10;
const COPY_FEEDBACK_DURATION_MS = 1500;
const STARTUP_REVEAL_DELAY_MS = 200;
const UNLOCK_SHAKE_RESET_MS = 350;
const MODAL_CLOSE_DURATION_MS = 100;
const TOAST_DURATION_MS = 3200;
const SECURITY_POLL_INTERVAL_MS = 15_000;
const CLIPBOARD_POPUP_WIDTH_PX = 360;
const CLIPBOARD_POPUP_MARGIN_PX = 16;
const CLIPBOARD_POPUP_OFFSET_PX = 12;
const CLIPBOARD_POPUP_FALLBACK_Y_PX = 96;
const CLIPBOARD_POPUP_MAX_TOP_PX = 170;
const IMPORT_FILE_EXTENSIONS = Object.freeze({
  bitwarden: ["json"],
  keepass: ["xml"],
  "1password": ["csv"],
  lastpass: ["csv"],
  dashlane: ["csv"],
  generic: ["csv"]
});
const EXPORT_FILE_EXTENSIONS = Object.freeze({
  encrypted: ["vg"],
  keepass: ["xml"],
  bitwarden: ["json"]
});
let introPlayed = false;

const state = {
  ready: false,
  vaultExists: false,
  unlocked: false,
  view: "entries",
  filters: {
    query: "",
    categoryId: "all",
    tag: "all",
    favoritesOnly: false
  },
  entries: [],
  categories: [],
  trash: [],
  selectedEntryId: null,
  selectedEntry: null,
  selectedEntryStrength: null,
  bruteForceStatus: null,
  securityStatus: null,
  ui: {
    unlockShake: false,
    revealDetailPassword: false,
    clipboardChoice: null,
    clipboardCountdown: null,
    clipboardHasContent: false,
    theme: "dark",
    modalClosing: false,
    postLoginLoading: false,
    startupIntro: {
      active: false
    },
    fileProtectionSupported: false,
    startupIntegrityAlert: null
  },
  toasts: [],
  forms: {
    setup: {
      password: "",
      confirmPassword: "",
      showPassword: false,
      showConfirmPassword: false,
      strength: null
    },
    setupConfirmation: {
      stage: null,
      readyChecked: false
    },
    unlock: {
      password: "",
      showPassword: false
    },
    entry: {
      open: false,
      mode: "create",
      draft: emptyEntryDraft(),
      revealPassword: false,
      strength: null
    },
    category: {
      open: false,
      editingId: null,
      draft: {
        name: "",
        emoji: "📁",
        color: "#7c6fe0"
      }
    },
    generator: {
      open: false,
      ...DEFAULT_GENERATOR_STATE,
      value: "",
      strength: null,
      target: "entry"
    },
    settings: {
      open: false,
      auto_lock_minutes: 5,
      clipboard_mode: "timed",
      clipboard_timeout_secs: DEFAULT_CLIPBOARD_TIMEOUT_SECS,
      clipboard_remember_choice: false,
      language: "en",
      theme: "dark",
      expanded_section: "general"
    },
    import: {
      open: false,
      type: "bitwarden",
      filePath: "",
      fileName: "",
      preview: null
    },
    export: {
      open: false,
      password: ""
    },
    masterPasswordPrompt: {
      open: false,
      password: "",
      resumeSettingsSection: "data"
    },
    changePassword: {
      open: false,
      currentPassword: "",
      newPassword: "",
      confirmNewPassword: "",
      strength: null
    },
    confirm: {
      open: false,
      kind: null,
      title: "",
      message: "",
      confirmLabel: "",
      url: null,
      entryId: null,
      categoryId: null
    }
  }
};

let clipboardTicker = null;
let clipboardChoiceDismissTimer = null;
let clipboardChoiceTicker = null;
let lockoutTicker = null;
let securityPoller = null;
let autoLockTimer = null;
let startupTimers = [];
let startupRunId = 0;
let dragEntryState = null;
let activeDropCategoryButton = null;
let activeDropCard = null;
let masterPasswordPromptResolver = null;

const strengthDebouncers = new Map();

export async function initializeApp() {
  if (state.ready) {
    return;
  }

  root = document.querySelector("#app");
  if (!root) {
    throw new Error("VaultGuard root element was not found.");
  }

  applyTheme(resolveInitialTheme());
  await initI18n("en");
  bindGlobalListeners();
  await bindTauriListeners();
  await bootstrap();
}

function bindGlobalListeners() {
  root.addEventListener("click", handleClick);
  root.addEventListener("pointerdown", handlePointerDown);
  root.addEventListener("submit", handleSubmit);
  root.addEventListener("input", handleInput);
  root.addEventListener("change", handleChange);
  root.addEventListener("dragstart", handleDragStart);
  root.addEventListener("dragover", handleDragOver);
  root.addEventListener("drop", handleDrop);
  root.addEventListener("dragend", handleDragEnd);

  document.addEventListener("keydown", handleKeyboardShortcuts);
  document.addEventListener("pointerdown", resetAutoLockTimer);
  document.addEventListener("keydown", resetAutoLockTimer);
  document.addEventListener("mousemove", throttle(resetAutoLockTimer, 2500));
  document.addEventListener("visibilitychange", async () => {
    if (document.hidden && state.unlocked) {
      await performLock(t("messages.vaultLocked"));
    }
  });
}

async function bindTauriListeners() {
  const listen = window.__TAURI__?.event?.listen;
  if (typeof listen !== "function") {
    return;
  }

  await listen("clipboard-countdown", (event) => {
    const timeout = event.payload?.timeout_secs ?? 0;
    if (!timeout) {
      return;
    }

    startClipboardCountdown(timeout);
  });

  await listen("clipboard-cleared", () => {
    clearClipboardCountdown();
    clearClipboardChoice();
    state.ui.clipboardHasContent = false;
    patchClipboardState();
    toast(t("messages.clipboardCleared"));
  });
}

async function bootstrap() {
  try {
    const integrityStatus = await vaultApi.getStartupIntegrityStatus();
    state.ui.fileProtectionSupported = Boolean(integrityStatus.supported);
    state.ui.startupIntegrityAlert = integrityStatus.blocked ? integrityStatus.message : null;

    if (integrityStatus.blocked) {
      return;
    }

    state.vaultExists = await vaultApi.checkVaultExists();
    state.bruteForceStatus = state.vaultExists ? await vaultApi.getBruteForceStatus() : null;
    syncLockoutTicker();

    if (state.vaultExists) {
      state.unlocked = await vaultApi.checkVaultUnlocked();
      if (state.unlocked) {
        await vaultApi.lockVault();
        state.unlocked = false;
      }
    }
  } catch (error) {
    toast(error.message, "error");
  } finally {
    state.ready = true;
    state.ui.startupIntro.active =
      !introPlayed && !state.unlocked && !state.ui.startupIntegrityAlert;
    render();
    startStartupIntro();
  }
}

function render() {
  const derived = buildDerivedState();
  document.documentElement.lang = getLanguage();
  document.title = t("app.name");
  root.innerHTML = renderApp({
    state,
    derived,
    t,
    formatDateTime
  });
  syncSetupPasswordChecklist();
  syncSetupConfirmationButton();
}

function clearStartupTimers() {
  startupTimers.forEach((timer) => clearTimeout(timer));
  startupTimers = [];
}

function queueStartupDelay(delayMs, callback) {
  const timer = setTimeout(() => {
    startupTimers = startupTimers.filter((scheduled) => scheduled !== timer);
    callback();
  }, delayMs);
  startupTimers.push(timer);
  return timer;
}

function animateIntroElement(element, keyframes, options) {
  if (!element) {
    return Promise.resolve();
  }

  return element
    .animate(keyframes, { fill: "forwards", ...options })
    .finished.catch(() => undefined);
}

function isStartupRunActive(runId) {
  return runId === startupRunId && state.ui.startupIntro.active;
}

function revealStartupContent() {
  root.querySelector("[data-startup-content]")?.classList.add("is-visible");
}

function cancelStartupAnimations() {
  root.querySelectorAll("#startup-overlay, #startup-icon, #vault-flash").forEach((node) => {
    node.getAnimations().forEach((animation) => animation.cancel());
  });
}

async function startStartupIntro() {
  if (introPlayed || !state.ready || state.unlocked || !state.ui.startupIntro.active) {
    return;
  }

  clearStartupTimers();
  const runId = ++startupRunId;
  const overlay = document.getElementById("startup-overlay");
  const icon = document.getElementById("startup-icon");
  const flash = document.getElementById("vault-flash");

  if (!overlay || !icon || !flash) {
    finishStartupIntro();
    return;
  }

  try {
    await animateIntroElement(
      icon,
      [
        { opacity: 0, transform: "scale(0.6)" },
        { opacity: 1, transform: "scale(1.0)" }
      ],
      { duration: 500, easing: "cubic-bezier(0.16, 1, 0.3, 1)" }
    );
    if (!isStartupRunActive(runId)) {
      return;
    }

    await Promise.all([
      animateIntroElement(
        icon,
        [
          { transform: "scale(1.0) rotate(0deg) translateX(0)" },
          { transform: "scale(1.0) rotate(-42deg) translateX(-2px)", offset: 0.25 },
          { transform: "scale(1.0) rotate(18deg) translateX(1px)", offset: 0.5 },
          { transform: "scale(1.0) rotate(-28deg) translateX(-1px)", offset: 0.75 },
          { transform: "scale(1.0) rotate(0deg) translateX(0)" }
        ],
        { duration: 900, easing: "ease-in-out" }
      ),
      animateIntroElement(
        icon,
        [
          {
            filter:
              "drop-shadow(0 0 80px rgba(124,111,224,1)) drop-shadow(0 0 120px rgba(124,111,224,0.5))"
          },
          {
            filter:
              "drop-shadow(0 0 36px rgba(124,111,224,0.35)) drop-shadow(0 0 72px rgba(124,111,224,0.18))",
            offset: 0.5
          },
          {
            filter:
              "drop-shadow(0 0 80px rgba(124,111,224,1)) drop-shadow(0 0 120px rgba(124,111,224,0.5))"
          }
        ],
        { duration: 900, easing: "ease-in-out" }
      )
    ]);
    if (!isStartupRunActive(runId)) {
      return;
    }

    await Promise.all([
      animateIntroElement(
        icon,
        [
          { transform: "scale(1.0) rotate(0deg)" },
          { transform: "scale(0.93) rotate(0deg)", offset: 0.2 },
          { transform: "scale(1.09) rotate(0deg)", offset: 0.6 },
          { transform: "scale(1.0) rotate(0deg)" }
        ],
        { duration: 400, easing: "ease-out" }
      ),
      animateIntroElement(
        flash,
        [
          { opacity: 0, transform: "scale(0.2)" },
          { opacity: 0.9, offset: 0.3 },
          { opacity: 0, transform: "scale(4.0)" }
        ],
        { duration: 500, easing: "ease-out" }
      )
    ]);
    if (!isStartupRunActive(runId)) {
      return;
    }

    queueStartupDelay(STARTUP_REVEAL_DELAY_MS, () => {
      if (isStartupRunActive(runId)) {
        revealStartupContent();
      }
    });

    await animateIntroElement(
      icon,
      [
        { transform: "scale(1.0)", opacity: 1 },
        { transform: "scale(9.0)", opacity: 0 }
      ],
      { duration: 600, easing: "cubic-bezier(0.55, 0, 1, 0.45)" }
    );
    if (!isStartupRunActive(runId)) {
      return;
    }

    finishStartupIntro();
  } catch {
    finishStartupIntro();
  }
}

function finishStartupIntro() {
  if (!state.ui.startupIntro.active && introPlayed) {
    return;
  }

  introPlayed = true;
  clearStartupTimers();
  cancelStartupAnimations();
  state.ui.startupIntro.active = false;
  render();
}

function skipStartupIntro() {
  if (!state.ui.startupIntro.active) {
    return;
  }

  startupRunId += 1;
  finishStartupIntro();
}

function handlePointerDown(event) {
  if (!(event.target instanceof HTMLElement)) {
    return;
  }

  const startupOverlay = event.target.closest("[data-startup-overlay]");
  if (!startupOverlay || !state.ui.startupIntro.active) {
    return;
  }

  event.preventDefault();
  skipStartupIntro();
}

async function showPostLoginLoading(loadPromiseFactory) {
  state.ui.postLoginLoading = true;
  render();

  try {
    await Promise.all([loadPromiseFactory(), delay(900)]);
  } finally {
    state.ui.postLoginLoading = false;
    render();
  }
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function buildDerivedState() {
  const categoryById = Object.fromEntries(state.categories.map((category) => [category.id, category]));
  const visibleEntries = filterEntries(state.entries, state.filters.query, state.filters);
  const selectedRecord =
    state.view === "trash"
      ? state.trash.find((item) => item.entry.id === state.selectedEntryId) || null
      : state.selectedEntry;

  const heading = state.filters.favoritesOnly
    ? t("common.favorites")
    : state.filters.categoryId !== "all"
      ? categoryById[state.filters.categoryId]?.name || t("vault.allItems")
      : t("vault.allItems");

  return {
    categories: [...state.categories].sort((left, right) => left.sort_order - right.sort_order),
    categoryById,
    visibleEntries,
    trashEntries: state.trash,
    tags: collectTags(state.entries),
    selectedRecord,
    heading,
    entryCount: state.entries.length,
    securityStatus: state.securityStatus
  };
}

function isVaultWorkspaceActive() {
  return Boolean(state.ready && state.vaultExists && state.unlocked && root.querySelector(".workspace-main"));
}

function patchEntryPanels() {
  if (!isVaultWorkspaceActive()) {
    return;
  }

  const derived = buildDerivedState();
  if (state.view === "entries" && state.selectedEntryId) {
    const visibleIds = new Set(derived.visibleEntries.map(({ entry }) => entry.id));
    if (!visibleIds.has(state.selectedEntryId)) {
      state.selectedEntryId = null;
      state.selectedEntry = null;
      state.selectedEntryStrength = null;
    }
  }

  const listPanel = root.querySelector(".panel-list");
  const detailPanel = root.querySelector(".panel-detail");
  const nextDerived = buildDerivedState();

  if (listPanel) {
    listPanel.innerHTML = renderEntryList(state, nextDerived, t, formatDateTime);
  }

  if (detailPanel) {
    detailPanel.classList.toggle("detail-open", Boolean(nextDerived.selectedRecord));
    detailPanel.innerHTML = renderDetailPanel(state, nextDerived, t, formatDateTime);
  }
}

function patchToastLayer() {
  const existing = root.querySelector(".toast-stack");
  const markup = renderToasts(state);

  if (existing) {
    existing.outerHTML = markup;
  } else {
    root.insertAdjacentHTML("beforeend", markup);
  }
}

function patchSettingsAccordion() {
  const sections = root.querySelectorAll("[data-settings-section]");
  if (!sections.length) {
    return;
  }

  sections.forEach((section) => {
    const isOpen = section.dataset.settingsSection === state.forms.settings.expanded_section;
    section.classList.toggle("is-open", isOpen);
    const toggle = section.querySelector(".settings-accordion-toggle");
    if (toggle) {
      toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    }
  });
}

function patchClipboardState() {
  render();
}

function applyDisabledButtonState(button, enabled) {
  if (!button) {
    return;
  }

  button.disabled = !enabled;
  button.style.opacity = enabled ? "1" : "0.4";
  button.style.cursor = enabled ? "pointer" : "not-allowed";
}

function buildMasterPasswordChecks(password) {
  const value = password || "";
  return [
    {
      id: "check-length",
      met: Array.from(value).length >= 15
    },
    {
      id: "check-upper",
      met: /[A-Z]/.test(value)
    },
    {
      id: "check-lower",
      met: /[a-z]/.test(value)
    },
    {
      id: "check-digit",
      met: /\d/.test(value)
    },
    {
      id: "check-special",
      met: /[^A-Za-z0-9]/.test(value)
    }
  ];
}

function syncSetupPasswordChecklist() {
  const input = root.querySelector("#master-password-input");
  const checklist = root.querySelector("#password-checklist");
  const submitButton = root.querySelector("#create-vault-btn");
  if (!input || !checklist || !submitButton) {
    return;
  }

  if (state.forms.setup.password !== input.value) {
    state.forms.setup.password = input.value;
  }

  const checks = buildMasterPasswordChecks(input.value);
  const allMet = checks.every((check) => check.met);

  checks.forEach(({ id, met }) => {
    const item = checklist.querySelector(`[data-check="${id}"]`);
    if (!item) {
      return;
    }

    item.classList.toggle("is-met", met);
    item.classList.toggle("is-unmet", !met);

    const icon = item.querySelector(".password-checklist-icon");
    if (icon) {
      icon.textContent = met ? "✓" : "✗";
    }
  });

  applyDisabledButtonState(submitButton, allMet);
}

function syncSetupConfirmationButton() {
  const checkbox = root.querySelector("#confirm-checkbox");
  const readyButton = root.querySelector("#confirm-ready-btn");
  if (!checkbox || !readyButton) {
    return;
  }

  applyDisabledButtonState(readyButton, checkbox.checked);
}

function formatClockCountdown(totalSeconds) {
  const seconds = Math.max(0, Number(totalSeconds) || 0);
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}:${String(remainder).padStart(2, "0")}`;
}

function updateClipboardCountdownDisplay() {
  const countdown = root.querySelector("[data-clipboard-countdown]");
  if (!countdown) {
    return;
  }

  if (!state.ui.clipboardCountdown) {
    countdown.classList.add("is-hidden");
    countdown.textContent = t("vault.clipboardCountdown", { time: "0:00" });
    return;
  }

  countdown.classList.remove("is-hidden");
  countdown.textContent = t("vault.clipboardCountdown", {
    time: formatClockCountdown(state.ui.clipboardCountdown.remaining)
  });
}

function updateClipboardChoiceDisplay() {
  const dismiss = root.querySelector("[data-clipboard-choice-dismiss]");
  if (!dismiss) {
    return;
  }

  dismiss.textContent = t("vault.clipboardChoiceDismiss", {
    seconds: Math.max(0, state.ui.clipboardChoice?.remaining || 0)
  });
}

function updateLockoutCountdownDisplay() {
  const countdown = root.querySelector("[data-lockout-countdown]");
  if (!countdown || !state.bruteForceStatus?.is_locked_out) {
    return;
  }

  const totalSeconds = Math.max(0, state.bruteForceStatus.lockout_remaining_secs || 0);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  countdown.textContent =
    hours > 0
      ? `${hours} ${hours === 1 ? "hour" : "hours"} ${minutes} ${minutes === 1 ? "minute" : "minutes"}`
      : `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

function syncLockoutTicker() {
  if (lockoutTicker) {
    clearInterval(lockoutTicker);
    lockoutTicker = null;
  }

  if (state.unlocked || !state.bruteForceStatus?.is_locked_out) {
    return;
  }

  updateLockoutCountdownDisplay();
  lockoutTicker = setInterval(async () => {
    if (state.unlocked || !state.bruteForceStatus?.is_locked_out) {
      syncLockoutTicker();
      return;
    }

    state.bruteForceStatus.lockout_remaining_secs = Math.max(
      0,
      (state.bruteForceStatus.lockout_remaining_secs || 0) - 1
    );
    updateLockoutCountdownDisplay();

    if (state.bruteForceStatus.lockout_remaining_secs <= 0) {
      state.bruteForceStatus = await safeBruteForceStatus();
      syncLockoutTicker();
      render();
    }
  }, 1000);
}

function resolveInitialTheme() {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyTheme(theme) {
  state.ui.theme = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = state.ui.theme;
}

function nextCustomCategoryColor() {
  const customCount = state.categories.filter((category) => !category.built_in).length;
  return CUSTOM_CATEGORY_COLORS[customCount % CUSTOM_CATEGORY_COLORS.length];
}

function patchStrengthDisplay(scope) {
  const strength = getStrengthForScope(scope);
  const scopeRoot = root.querySelector(`[data-strength-scope="${scope}"]`);
  if (!scopeRoot) {
    return;
  }

  const label = scopeRoot.querySelector("[data-strength-label]");
  const meta = scopeRoot.querySelector("[data-strength-meta]");
  const fill = scopeRoot.querySelector("[data-strength-fill]");

  if (label) {
    label.textContent = strength?.scoreLabel || "—";
  }
  if (meta) {
    meta.textContent = strength?.crackTime
      ? `${t("entry.crackTime")}: ${strength.crackTime}`
      : getStrengthFallback(scope);
  }
  if (fill) {
    fill.dataset.level = strength?.level || "none";
  }
}

function patchGeneratorPanel() {
  const panel = root.querySelector(".inline-generator-panel");
  if (!panel) {
    return;
  }

  const output = panel.querySelector("[data-generator-output]");
  const lengthValue = panel.querySelector("[data-generator-length-value]");
  const wordCountValue = panel.querySelector("[data-generator-word-count-value]");
  const modeButtons = panel.querySelectorAll("[data-generator-mode-button]");

  if (output) {
    output.textContent = state.forms.generator.value || "—";
  }
  if (lengthValue) {
    lengthValue.textContent = String(state.forms.generator.length);
  }
  if (wordCountValue) {
    wordCountValue.textContent = String(state.forms.generator.word_count);
  }

  modeButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.mode === state.forms.generator.mode);
  });

  patchStrengthDisplay("generator");
}

function getStrengthForScope(scope) {
  switch (scope) {
    case "setup":
      return state.forms.setup.strength;
    case "entry":
      return state.forms.entry.strength;
    case "changePassword":
      return state.forms.changePassword.strength;
    case "generator":
      return state.forms.generator.strength;
    default:
      return null;
  }
}

function getStrengthFallback(scope) {
  return scope === "setup" ? t("setup.passwordHint") : "—";
}

function handleKeyboardShortcuts(event) {
  const isFormField = event.target instanceof HTMLElement && event.target.matches("input, textarea, select");
  const accelerator = event.ctrlKey || event.metaKey;
  const key = event.key.toLowerCase();

  if (accelerator && key === "f") {
    event.preventDefault();
    document.querySelector("#vault-search")?.focus();
    return;
  }

  if (isFormField && !accelerator && event.key !== "Escape") {
    return;
  }

  if (!state.unlocked) {
    return;
  }

  if (accelerator && key === "n") {
    event.preventDefault();
    openEntryModal(null);
    return;
  }

  if (accelerator && key === "l") {
    event.preventDefault();
    performLock(t("messages.vaultLocked"));
    return;
  }

  if (accelerator && key === "g") {
    event.preventDefault();
    if (!state.forms.entry.open) {
      openEntryModal(state.selectedEntryId || null).then(() => {
        state.forms.generator.open = true;
        regeneratePassword().then(render);
      });
      return;
    }
    state.forms.generator.open = true;
    regeneratePassword().then(render);
    return;
  }

  if (event.key === "?") {
    event.preventDefault();
    openSettingsModal("shortcuts");
    return;
  }

  if (event.key === "Escape") {
    if (hasOpenModal()) {
      closeModal();
      return;
    }
    if (state.selectedEntryId) {
      state.selectedEntryId = null;
      state.selectedEntry = null;
      patchEntryPanels();
    }
  }
}

async function handleClick(event) {
  if (event.target instanceof HTMLElement && event.target.matches("[data-modal-backdrop]")) {
    closeModal();
    return;
  }

  const actionTarget = event.target.closest("[data-action]");
  if (!actionTarget) {
    return;
  }

  const action = actionTarget.dataset.action;

  switch (action) {
    case "skip-startup-intro":
      skipStartupIntro();
      break;
    case "show-all":
      state.view = "entries";
      state.filters.categoryId = "all";
      state.filters.favoritesOnly = false;
      state.selectedEntryId = null;
      state.selectedEntry = null;
      state.selectedEntryStrength = null;
      render();
      break;
    case "show-trash":
      state.view = "trash";
      state.selectedEntry = null;
      state.selectedEntryId = null;
      render();
      break;
    case "reset-filters":
      state.view = "entries";
      state.filters = { query: "", categoryId: "all", tag: "all", favoritesOnly: false };
      patchEntryPanels();
      break;
    case "filter-category":
      state.view = "entries";
      state.filters.categoryId = actionTarget.dataset.categoryId || "all";
      state.filters.favoritesOnly = false;
      state.selectedEntryId = null;
      state.selectedEntry = null;
      state.selectedEntryStrength = null;
      render();
      break;
    case "select-entry":
      await selectEntry(actionTarget.dataset.entryId);
      break;
    case "select-trash-entry":
      state.selectedEntryId = actionTarget.dataset.entryId;
      render();
      break;
    case "open-entry-modal":
      await openEntryModal(actionTarget.dataset.entryId || null);
      break;
    case "delete-entry":
      openConfirmDialog({
        kind: "delete-entry",
        title: t("common.delete"),
        message: t("messages.confirmDeleteEntry"),
        confirmLabel: t("common.delete"),
        entryId: actionTarget.dataset.entryId
      });
      break;
    case "restore-entry":
      await withHandledError(async () => {
        await vaultApi.restoreEntry(actionTarget.dataset.entryId);
        toast(t("messages.entryRestored"));
        await loadVaultData();
      });
      break;
    case "permanent-delete":
      openConfirmDialog({
        kind: "permanent-delete",
        title: t("common.delete"),
        message: t("messages.confirmPermanentDelete"),
        confirmLabel: t("common.delete"),
        entryId: actionTarget.dataset.entryId
      });
      break;
    case "copy-username":
      await copySelectedField("username", actionTarget);
      break;
    case "copy-password":
      await copySelectedField("password", actionTarget);
      break;
    case "copy-url":
      await copySelectedField("url", actionTarget);
      break;
    case "toggle-detail-password":
      state.ui.revealDetailPassword = !state.ui.revealDetailPassword;
      patchEntryPanels();
      break;
    case "prompt-open-url":
      if (state.selectedEntry?.url) {
        openConfirmDialog({
          kind: "open-url",
          title: t("common.open"),
          message: `${t("entry.openUrlConfirm")} [${state.selectedEntry.url}]`,
          confirmLabel: t("common.yes"),
          url: state.selectedEntry.url
        });
      }
      break;
    case "open-repo-link":
      openConfirmDialog({
        kind: "open-url",
        title: t("common.open"),
        message: `${t("entry.openUrlConfirm")} [https://github.com/Viperzz6988/VaultGuard]`,
        confirmLabel: t("common.yes"),
        url: "https://github.com/Viperzz6988/VaultGuard"
      });
      break;
    case "close-detail":
      state.selectedEntryId = null;
      state.selectedEntry = null;
      state.selectedEntryStrength = null;
      patchEntryPanels();
      break;
    case "lock-vault":
      await animateLockButtonAndLock(actionTarget);
      break;
    case "clear-clipboard":
      await withHandledError(async () => {
        await vaultApi.clearClipboard();
        clearClipboardChoice();
        clearClipboardCountdown();
        state.ui.clipboardHasContent = false;
        patchClipboardState();
        toast(t("messages.clipboardCleared"));
      });
      break;
    case "clipboard-choice-confirm":
      await confirmClipboardChoice();
      break;
    case "clipboard-choice-cancel":
      cancelClipboardChoice();
      break;
    case "toggle-theme":
      applyTheme(state.ui.theme === "dark" ? "light" : "dark");
      render();
      break;
    case "open-settings-modal":
      openSettingsModal(actionTarget.dataset.section || "general");
      break;
    case "open-change-password-modal":
      state.forms.settings.open = false;
      state.forms.changePassword.open = true;
      render();
      break;
    case "reset-clipboard-preference":
      await resetClipboardPreference();
      break;
    case "delete-category":
      openConfirmDialog({
        kind: "delete-category",
        title: t("common.delete"),
        message: t("messages.confirmDeleteCategory"),
        confirmLabel: t("common.delete"),
        categoryId: actionTarget.dataset.categoryId
      });
      break;
    case "open-category-popover":
      state.forms.category.open = true;
      state.forms.category.editingId = null;
      state.forms.category.draft = { name: "", emoji: "📁", color: nextCustomCategoryColor() };
      render();
      break;
    case "select-category-emoji":
      state.forms.category.draft.emoji = actionTarget.dataset.emoji || "📁";
      render();
      break;
    case "toggle-settings-section":
      state.forms.settings.expanded_section =
        state.forms.settings.expanded_section === actionTarget.dataset.section
          ? ""
          : actionTarget.dataset.section || "general";
      patchSettingsAccordion();
      break;
    case "choose-import-file-trigger":
      await chooseImportFile();
      break;
    case "toggle-setup-password":
      state.forms.setup.showPassword = !state.forms.setup.showPassword;
      render();
      break;
    case "toggle-setup-confirm-password":
      state.forms.setup.showConfirmPassword = !state.forms.setup.showConfirmPassword;
      render();
      break;
    case "acknowledge-master-password-warning":
      state.forms.setupConfirmation.stage = "confirm";
      render();
      break;
    case "cancel-master-password-confirmation":
      state.forms.setupConfirmation.stage = "warning";
      state.forms.setupConfirmation.readyChecked = false;
      render();
      break;
    case "finish-master-password-confirmation":
      if (!state.forms.setupConfirmation.readyChecked) {
        return;
      }
      if (state.ui.fileProtectionSupported) {
        state.forms.setupConfirmation.stage = "integrity";
        render();
        return;
      }
      state.forms.setupConfirmation = emptySetupConfirmationForm();
      await showPostLoginLoading(() => loadVaultData({ skipRender: true }));
      break;
    case "skip-integrity-protection":
      await finalizeFileProtectionChoice(false);
      break;
    case "enable-integrity-protection":
      await finalizeFileProtectionChoice(true);
      break;
    case "exit-app":
      await vaultApi.quitApp();
      break;
    case "toggle-unlock-password":
      state.forms.unlock.showPassword = !state.forms.unlock.showPassword;
      render();
      break;
    case "close-category-popover":
      state.forms.category.open = false;
      state.forms.category.editingId = null;
      state.forms.category.draft = { name: "", emoji: "📁", color: nextCustomCategoryColor() };
      render();
      break;
    case "toggle-entry-password":
      state.forms.entry.revealPassword = !state.forms.entry.revealPassword;
      render();
      break;
    case "toggle-entry-generator":
      state.forms.generator.open = !state.forms.generator.open;
      if (state.forms.generator.open) {
        state.forms.generator.target = "entry";
        await regeneratePassword();
      }
      render();
      break;
    case "set-generator-mode":
      state.forms.generator.mode = actionTarget.dataset.mode;
      await regeneratePassword();
      render();
      break;
    case "regenerate-password":
      await regeneratePassword();
      render();
      break;
    case "copy-generated-password":
      await withHandledError(async () => {
        await vaultApi.copyToClipboard(state.forms.generator.value);
        await handleClipboardCopy(actionTarget, t("common.password"));
      });
      break;
    case "use-generated-password":
      state.forms.entry.draft.password = state.forms.generator.value;
      state.forms.entry.open = true;
      scheduleStrengthUpdate("entry");
      render();
      break;
    case "toggle-favorite":
      event.stopPropagation();
      await toggleEntryFavorite(actionTarget.dataset.entryId);
      break;
    case "copy-entry-password":
      event.stopPropagation();
      await copyEntryPassword(actionTarget.dataset.entryId, actionTarget);
      break;
    case "run-import":
      await executeImport();
      break;
    case "run-export":
      await executeExport(actionTarget.dataset.exportType);
      break;
    case "confirm-action":
      await runConfirmAction();
      break;
    case "close-modal":
      closeModal();
      break;
    default:
      break;
  }
}

async function handleSubmit(event) {
  event.preventDefault();
  const form = event.target.dataset.form;
  if (!form) {
    return;
  }

  switch (form) {
    case "setup":
      await submitSetup(event.target);
      break;
    case "unlock":
      await submitUnlock(event.target);
      break;
    case "entry":
      await submitEntry(event.target);
      break;
    case "category":
      await submitCategory();
      break;
    case "settings":
      await submitSettings();
      break;
    case "change-password":
      await submitChangePassword();
      break;
    case "master-password-prompt":
      submitMasterPasswordPrompt();
      break;
    default:
      break;
  }
}

function handleInput(event) {
  const model = event.target.dataset.model;
  if (model) {
    updateModel(model, getInputValue(event.target));
  }

  if (event.target.dataset.customField) {
    const index = Number(event.target.dataset.index);
    const field = event.target.dataset.customField;
    state.forms.entry.draft.custom_fields[index][field] = getInputValue(event.target);
  }

  if (model === "setup.password") {
    syncSetupPasswordChecklist();
    scheduleStrengthUpdate("setup");
    return;
  }
  if (model === "setup.confirmPassword") {
    syncSetupPasswordChecklist();
    return;
  }
  if (model === "entry.password") {
    scheduleStrengthUpdate("entry");
    return;
  }
  if (model === "changePassword.newPassword") {
    scheduleStrengthUpdate("changePassword");
    return;
  }
  if (model?.startsWith("generator.")) {
    const normalized = normalizeGeneratorState(state.forms.generator);
    Object.assign(state.forms.generator, normalized);
    regeneratePassword().then(() => {
      patchGeneratorPanel();
    });
    return;
  }

  if (model === "filters.query") {
    patchEntryPanels();
    return;
  }

  if (model === "filters.categoryId" || model === "filters.tag") {
    patchEntryPanels();
    return;
  }
}

async function handleChange(event) {
  const model = event.target.dataset.model;
  if (model && !event.target.dataset.action) {
    updateModel(model, getInputValue(event.target));
    if (model === "setupConfirmation.readyChecked") {
      syncSetupConfirmationButton();
      return;
    }
    if (model.startsWith("clipboardChoice.")) {
      render();
      return;
    }
    if (model === "filters.categoryId" || model === "filters.tag") {
      patchEntryPanels();
      return;
    }
    return;
  }
}

function handleDragStart(event) {
  if (!(event.target instanceof HTMLElement)) {
    return;
  }

  const card = event.target.closest("[data-draggable-entry]");
  if (!card || state.view !== "entries") {
    return;
  }

  dragEntryState = {
    entryId: card.dataset.entryId || "",
    categoryId: card.dataset.entryCategoryId || "builtin-other"
  };

  card.classList.add("is-dragging");
  card.querySelector(".entry-card")?.classList.add("dragging");
  if (event.dataTransfer) {
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", dragEntryState.entryId);
  }
}

function handleDragOver(event) {
  if (!(event.target instanceof HTMLElement) || !dragEntryState) {
    clearActiveCategoryDropTarget();
    clearActiveDropCard();
    return;
  }

  const categoryTarget = event.target.closest("[data-drop-category-id]");
  if (categoryTarget) {
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "move";
    }
    setActiveCategoryDropTarget(categoryTarget);
    clearActiveDropCard();
    return;
  }

  if (!canReorderEntries()) {
    clearActiveCategoryDropTarget();
    clearActiveDropCard();
    return;
  }

  const cardTarget = event.target.closest("[data-reorder-entry-id]");
  if (cardTarget && cardTarget.dataset.reorderEntryId !== dragEntryState.entryId) {
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "move";
    }
    setActiveDropCard(cardTarget, event.clientY);
    clearActiveCategoryDropTarget();
    return;
  }

  clearActiveCategoryDropTarget();
  clearActiveDropCard();
}

async function handleDrop(event) {
  if (!(event.target instanceof HTMLElement) || !dragEntryState) {
    clearDragState();
    return;
  }

  const categoryTarget = event.target.closest("[data-drop-category-id]");
  if (categoryTarget) {
    event.preventDefault();
    const targetCategoryId = categoryTarget.dataset.dropCategoryId || "builtin-other";

    await withHandledError(async () => {
      await vaultApi.moveEntryToCategory(dragEntryState.entryId, targetCategoryId);
      await loadVaultData();
      animateDroppedEntry(dragEntryState.entryId);
    });
    clearDragState();
    return;
  }

  const cardTarget = event.target.closest("[data-reorder-entry-id]");
  if (cardTarget && canReorderEntries() && cardTarget.dataset.reorderEntryId !== dragEntryState.entryId) {
    event.preventDefault();
    const position = cardTarget.dataset.dropPosition || "after";

    await withHandledError(async () => {
      await vaultApi.reorderEntry(
        dragEntryState.entryId,
        cardTarget.dataset.reorderEntryId,
        position
      );
      await loadVaultData();
      animateDroppedEntry(dragEntryState.entryId);
    });
  }

  clearDragState();
}

function handleDragEnd() {
  clearDragState();
}

function canReorderEntries() {
  return state.view === "entries" && state.filters.categoryId !== "all" && !String(state.filters.query || "").trim();
}

function setActiveCategoryDropTarget(target) {
  if (activeDropCategoryButton === target) {
    return;
  }
  clearActiveCategoryDropTarget();
  activeDropCategoryButton = target;
  activeDropCategoryButton.classList.add("drag-over");
}

function clearActiveCategoryDropTarget() {
  activeDropCategoryButton?.classList.remove("drag-over");
  activeDropCategoryButton = null;
}

function setActiveDropCard(target, clientY) {
  const rect = target.getBoundingClientRect();
  const midY = rect.top + rect.height / 2;
  const dropPosition = clientY < midY ? "before" : "after";

  if (activeDropCard && activeDropCard !== target) {
    clearActiveDropCard();
  }

  activeDropCard = target;
  activeDropCard.dataset.dropPosition = dropPosition;
  activeDropCard.classList.remove("drop-target-before", "drop-target-after");
  activeDropCard.classList.add(dropPosition === "before" ? "drop-target-before" : "drop-target-after");
}

function clearActiveDropCard() {
  if (!activeDropCard) {
    return;
  }

  activeDropCard.classList.remove("drop-target-before", "drop-target-after");
  delete activeDropCard.dataset.dropPosition;
  activeDropCard = null;
}

function clearDragState() {
  root.querySelectorAll("[data-draggable-entry].is-dragging").forEach((node) => {
    node.classList.remove("is-dragging");
  });
  root.querySelectorAll(".entry-card.dragging").forEach((node) => {
    node.classList.remove("dragging");
  });
  clearActiveCategoryDropTarget();
  clearActiveDropCard();
  dragEntryState = null;
}

function animateDroppedEntry(entryId) {
  const card = root.querySelector(`[data-entry-id="${CSS.escape(entryId)}"] .entry-card`);
  if (!card) {
    return;
  }

  card.animate([{ transform: "scale(1.03)" }, { transform: "scale(1)" }], {
    duration: 200,
    easing: "ease-out"
  });
}

async function submitSetup() {
  if (!state.forms.setup.password) {
    toast(t("validation.masterPasswordRequired"), "error");
    return;
  }
  if (state.forms.setup.password !== state.forms.setup.confirmPassword) {
    toast(t("validation.passwordMismatch"), "error");
    return;
  }

  await withHandledError(async () => {
    const response = await vaultApi.createVault(state.forms.setup.password);
    state.vaultExists = true;
    state.unlocked = true;
    state.bruteForceStatus = response.brute_force_status;
    toast(t("setup.createdSuccess"));
    resetSetupForm();
    state.forms.setupConfirmation = {
      stage: "warning",
      readyChecked: false
    };
    render();
  });
}

async function submitUnlock() {
  try {
    const response = await vaultApi.unlockVault(state.forms.unlock.password);
    state.unlocked = true;
    state.ui.unlockShake = false;
    state.bruteForceStatus = response.brute_force_status;
    syncLockoutTicker();
    state.forms.unlock.password = "";
    state.forms.unlock.showPassword = false;
    await showPostLoginLoading(() => loadVaultData({ skipRender: true }));
  } catch (error) {
    if (error.code === "BackupRestoreAvailable") {
      openConfirmDialog({
        kind: "restore-backup",
        title: t("vault.restoreBackupTitle"),
        message: error.message,
        confirmLabel: t("vault.restoreBackupAction")
      });
      return;
    }

    state.ui.unlockShake = true;
    setTimeout(() => {
      state.ui.unlockShake = false;
      render();
    }, UNLOCK_SHAKE_RESET_MS);
    state.bruteForceStatus = state.vaultExists ? await safeBruteForceStatus() : null;
    syncLockoutTicker();
    toast(error.message, "error");
    render();
  }
}

async function submitEntry(formElement) {
  const formData = new FormData(formElement);
  const payload = buildEntryPayload(formData, state.forms.entry.draft);
  if (!payload.title) {
    toast(t("validation.titleRequired"), "error");
    return;
  }

  await withHandledError(async () => {
    let savedEntry;
    if (state.forms.entry.mode === "edit" && state.forms.entry.draft.id) {
      savedEntry = await vaultApi.updateEntry(state.forms.entry.draft.id, payload);
    } else {
      savedEntry = await vaultApi.createEntry(payload);
    }

    state.selectedEntryId = savedEntry.id;
    state.selectedEntry = savedEntry;
    state.selectedEntryStrength = savedEntry.password
      ? mapStrength(await vaultApi.checkPasswordStrength(savedEntry.password))
      : null;
    toast(t("messages.entrySaved"));
    state.ui.modalClosing = false;
    clearModalState();
    await loadVaultData({ skipRender: true });
    render();
  });
}

async function submitCategory() {
  if (!state.forms.category.draft.name.trim()) {
    toast(t("validation.categoryNameRequired"), "error");
    return;
  }

  await withHandledError(async () => {
    await vaultApi.createCategory({
      name: state.forms.category.draft.name.trim(),
      emoji: state.forms.category.draft.emoji || "📁",
      color: state.forms.category.draft.color || nextCustomCategoryColor()
    });
    toast(t("messages.categorySaved"));
    state.forms.category.open = false;
    state.forms.category.editingId = null;
    state.forms.category.draft = { name: "", emoji: "📁", color: nextCustomCategoryColor() };
    state.categories = await vaultApi.getCategories();
    render();
  });
}

async function submitSettings() {
  await withHandledError(async () => {
    applyTheme(state.forms.settings.theme);
    const settings = await vaultApi.updateSettings({
      auto_lock_minutes: Number(state.forms.settings.auto_lock_minutes),
      clipboard_mode: state.forms.settings.clipboard_mode,
      clipboard_timeout_secs: Number(state.forms.settings.clipboard_timeout_secs),
      clipboard_remember_choice: Boolean(state.forms.settings.clipboard_remember_choice),
      language: state.forms.settings.language
    });

    await setLanguage(settings.language);
    syncSettingsForm(settings, { open: false, expandedSection: "general" });
    toast(t("messages.settingsSaved"));
    scheduleSecurityPolling();
    resetAutoLockTimer();
    render();
  });
}

async function submitChangePassword() {
  const form = state.forms.changePassword;
  if (form.newPassword !== form.confirmNewPassword) {
    toast(t("validation.passwordMismatch"), "error");
    return;
  }

  await withHandledError(async () => {
    await vaultApi.changeMasterPassword(form.currentPassword, form.newPassword);
    state.forms.changePassword = emptyChangePasswordForm();
    toast(t("messages.passwordChanged"));
    render();
  });
}

function updateModel(path, value) {
  switch (path) {
    case "setup.password":
      state.forms.setup.password = value;
      break;
    case "setup.confirmPassword":
      state.forms.setup.confirmPassword = value;
      break;
    case "setupConfirmation.readyChecked":
      state.forms.setupConfirmation.readyChecked = Boolean(value);
      break;
    case "unlock.password":
      state.forms.unlock.password = value;
      break;
    case "filters.query":
      state.filters.query = value;
      break;
    case "filters.categoryId":
      state.filters.categoryId = value || "all";
      state.view = "entries";
      break;
    case "filters.tag":
      state.filters.tag = value || "all";
      break;
    case "entry.title":
      state.forms.entry.draft.title = value;
      break;
    case "entry.username":
      state.forms.entry.draft.username = value;
      break;
    case "entry.password":
      state.forms.entry.draft.password = value;
      break;
    case "entry.url":
      state.forms.entry.draft.url = value;
      break;
    case "entry.category_id":
      state.forms.entry.draft.category_id = value || "builtin-login";
      break;
    case "category.name":
      state.forms.category.draft.name = value;
      break;
    case "category.emoji":
      state.forms.category.draft.emoji = value;
      break;
    case "category.color":
      state.forms.category.draft.color = value;
      break;
    case "settings.auto_lock_minutes":
      state.forms.settings.auto_lock_minutes = Number(value);
      break;
    case "settings.clipboard_timeout_secs":
      state.forms.settings.clipboard_timeout_secs = Number(value) || DEFAULT_CLIPBOARD_TIMEOUT_SECS;
      break;
    case "clipboardChoice.mode":
      if (state.ui.clipboardChoice) {
        state.ui.clipboardChoice.mode = value === "manual" ? "manual" : "timed";
      }
      break;
    case "clipboardChoice.remember":
      if (state.ui.clipboardChoice) {
        state.ui.clipboardChoice.remember = Boolean(value);
      }
      break;
    case "settings.language":
      state.forms.settings.language = value;
      break;
    case "settings.theme":
      state.forms.settings.theme = value === "light" ? "light" : "dark";
      applyTheme(state.forms.settings.theme);
      break;
    case "generator.length":
      state.forms.generator.length = Number(value);
      break;
    case "generator.word_count":
      state.forms.generator.word_count = Number(value);
      break;
    case "generator.separator":
      state.forms.generator.separator = value;
      break;
    case "generator.uppercase":
    case "generator.lowercase":
    case "generator.numbers":
    case "generator.symbols":
    case "generator.exclude_ambiguous": {
      const key = path.split(".")[1];
      state.forms.generator[key] = Boolean(value);
      break;
    }
    case "import.type":
      state.forms.import.type = value;
      if (state.forms.import.fileName) {
        state.forms.import.filePath = "";
        state.forms.import.fileName = "";
      }
      break;
    case "masterPasswordPrompt.password":
      state.forms.masterPasswordPrompt.password = value;
      break;
    case "changePassword.currentPassword":
      state.forms.changePassword.currentPassword = value;
      break;
    case "changePassword.newPassword":
      state.forms.changePassword.newPassword = value;
      break;
    case "changePassword.confirmNewPassword":
      state.forms.changePassword.confirmNewPassword = value;
      break;
    default:
      break;
  }
}

async function openEntryModal(entryId) {
  state.forms.entry.open = true;
  state.forms.entry.revealPassword = false;
  state.forms.entry.strength = null;

  if (entryId) {
    const entry = state.selectedEntry?.id === entryId ? state.selectedEntry : await vaultApi.getEntry(entryId);
    state.forms.entry.mode = "edit";
    state.forms.entry.draft = draftFromEntry(entry);
  } else {
    state.forms.entry.mode = "create";
    state.forms.entry.draft = emptyEntryDraft(
      state.filters.categoryId !== "all" ? state.filters.categoryId : "builtin-login"
    );
  }

  scheduleStrengthUpdate("entry");
  render();
}

function openSettingsModal(section = "general") {
  state.forms.category.open = false;
  state.forms.entry.open = false;
  state.forms.generator.open = false;
  state.forms.changePassword.open = false;
  state.forms.confirm = emptyConfirmForm();
  state.forms.settings.open = true;
  state.forms.settings.theme = state.ui.theme;
  state.forms.settings.expanded_section = section;
  render();
}

async function selectEntry(entryId) {
  await withHandledError(async () => {
    state.view = "entries";
    state.selectedEntryId = entryId;
    state.ui.revealDetailPassword = false;
    state.selectedEntry = await vaultApi.getEntry(entryId);
    state.selectedEntryStrength = state.selectedEntry.password
      ? mapStrength(await vaultApi.checkPasswordStrength(state.selectedEntry.password))
      : null;
    render();
  });
}

async function regeneratePassword() {
  const generator = normalizeGeneratorState(state.forms.generator);
  Object.assign(state.forms.generator, generator);

  await withHandledError(async () => {
    state.forms.generator.value =
      generator.mode === "passphrase"
        ? await vaultApi.generatePassphrase(generator.word_count, generator.separator)
        : await vaultApi.generatePassword({
            length: generator.length,
            uppercase: generator.uppercase,
            lowercase: generator.lowercase,
            numbers: generator.numbers,
            symbols: generator.symbols,
            exclude_ambiguous: generator.exclude_ambiguous
          });

    const strength = await vaultApi.checkPasswordStrength(state.forms.generator.value);
    state.forms.generator.strength = mapStrength(strength);
  });
}

async function loadVaultData(options = {}) {
  const { skipRender = false } = options;
  const settingsModalWasOpen = state.forms.settings.open;
  const expandedSection = state.forms.settings.expanded_section || "general";
  const [entries, categories, trash, settings, securityStatus] = await Promise.all([
    vaultApi.getEntries(),
    vaultApi.getCategories(),
    vaultApi.getTrash(),
    vaultApi.getSettings(),
    vaultApi.getVaultFileStatus()
  ]);

  state.entries = entries;
  state.categories = categories;
  state.trash = trash;
  state.securityStatus = securityStatus;
  state.unlocked = true;

  if (settings.language !== getLanguage()) {
    await setLanguage(settings.language);
  }

  syncSettingsForm(settings, { open: settingsModalWasOpen, expandedSection });

  if (state.selectedEntryId && state.view === "entries") {
    const stillExists = state.entries.find((entry) => entry.id === state.selectedEntryId);
    state.selectedEntry = stillExists ? await vaultApi.getEntry(state.selectedEntryId) : null;
    state.selectedEntryStrength = state.selectedEntry?.password
      ? mapStrength(await vaultApi.checkPasswordStrength(state.selectedEntry.password))
      : null;
    if (!stillExists) {
      state.selectedEntryId = null;
      state.selectedEntryStrength = null;
    }
  } else if (!state.selectedEntryId) {
    state.selectedEntryStrength = null;
  }

  scheduleSecurityPolling();
  resetAutoLockTimer();
  if (!skipRender) {
    render();
  }
}

async function executeImport() {
  if (!state.forms.import.filePath) {
    toast(t("validation.fileRequired"), "error");
    return;
  }

  await withHandledError(async () => {
    const count = await vaultApi.importVaultData(
      state.forms.import.filePath,
      state.forms.import.type
    );

    toast(t("messages.importFinished", { count }), "success");
    state.forms.import = {
      open: false,
      type: "bitwarden",
      filePath: "",
      fileName: "",
      preview: null
    };
    await loadVaultData();
  });
}

async function chooseImportFile() {
  await withHandledError(async () => {
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: "Import file",
          extensions: IMPORT_FILE_EXTENSIONS[state.forms.import.type] ?? ["json", "xml", "csv"]
        }
      ]
    });

    if (!selected || Array.isArray(selected)) {
      return;
    }

    state.forms.import.filePath = selected;
    state.forms.import.fileName = selected.split(/[\\/]/).pop() || selected;
    render();
  });
}

async function executeExport(type) {
  const password = await promptMasterPassword();
  if (!password) {
    openSettingsModal("data");
    return;
  }

  const extensions = EXPORT_FILE_EXTENSIONS[type];
  if (!extensions) {
    toast(t("validation.invalidImport"), "error");
    openSettingsModal("data");
    return;
  }

  const filePath = await save({
    filters: [
      {
        name: "VaultGuard export",
        extensions
      }
    ],
    defaultPath: `vaultguard-export.${extensions[0]}`
  });

  if (!filePath || Array.isArray(filePath)) {
    openSettingsModal("data");
    return;
  }

  await withHandledError(async () => {
    await vaultApi.exportVaultData(filePath, type, password);
    toast(t("messages.exportReady"), "success");
  });

  openSettingsModal("data");
}

async function finalizeFileProtectionChoice(enabled) {
  await withHandledError(async () => {
    const status = await vaultApi.configureFileProtection(enabled);
    state.ui.fileProtectionSupported = Boolean(status.supported);
    state.ui.startupIntegrityAlert = status.blocked ? status.message : null;
    state.forms.setupConfirmation = emptySetupConfirmationForm();

    if (state.ui.startupIntegrityAlert) {
      render();
      return;
    }

    await showPostLoginLoading(() => loadVaultData({ skipRender: true }));
  });
}

function promptMasterPassword() {
  return new Promise((resolve) => {
    if (masterPasswordPromptResolver) {
      masterPasswordPromptResolver(null);
    }

    masterPasswordPromptResolver = resolve;
    state.forms.settings.open = false;
    state.forms.masterPasswordPrompt = {
      open: true,
      password: "",
      resumeSettingsSection: "data"
    };
    render();
  });
}

function resolveMasterPasswordPrompt(password) {
  const resolver = masterPasswordPromptResolver;
  masterPasswordPromptResolver = null;
  state.forms.masterPasswordPrompt = emptyMasterPasswordPromptForm();
  if (resolver) {
    resolver(password);
  }
}

function submitMasterPasswordPrompt() {
  const password = state.forms.masterPasswordPrompt.password;
  if (!password) {
    toast(t("validation.masterPasswordRequired"), "error");
      return;
  }

  resolveMasterPasswordPrompt(password);
}

async function performLock(message) {
  clearAutoLockTimer();
  clearClipboardChoice();
  clearClipboardCountdown();
  state.ui.clipboardHasContent = false;
  clearSecurityPolling();
  syncLockoutTicker();
  await withHandledError(async () => {
    await vaultApi.lockVault();
    state.unlocked = false;
    state.ui.postLoginLoading = false;
    state.view = "entries";
    state.filters = { query: "", categoryId: "all", tag: "all", favoritesOnly: false };
    state.entries = [];
    state.trash = [];
    state.selectedEntry = null;
    state.selectedEntryId = null;
    state.selectedEntryStrength = null;
    state.securityStatus = null;
    state.forms.setupConfirmation = emptySetupConfirmationForm();
    closeModal(true);
    toast(message);
    render();
  });
}

function hasOpenModal() {
  return [
    state.forms.entry.open,
    state.forms.settings.open,
    state.forms.changePassword.open,
    state.forms.masterPasswordPrompt.open,
    state.forms.confirm.open
  ].some(Boolean);
}

function clearModalState() {
  state.forms.entry.open = false;
  state.forms.generator.open = false;
  state.forms.settings.open = false;
  state.forms.changePassword.open = false;
  state.forms.masterPasswordPrompt = emptyMasterPasswordPromptForm();
  state.forms.confirm = emptyConfirmForm();
}

function closeModal(immediate = false) {
  if (immediate || state.ui.modalClosing || !hasOpenModal()) {
    if (state.forms.masterPasswordPrompt.open) {
      resolveMasterPasswordPrompt(null);
    }
    state.ui.modalClosing = false;
    clearModalState();
    render();
    return;
  }

  state.ui.modalClosing = true;
  render();
  setTimeout(() => {
    if (state.forms.masterPasswordPrompt.open) {
      resolveMasterPasswordPrompt(null);
    }
    state.ui.modalClosing = false;
    clearModalState();
    render();
  }, MODAL_CLOSE_DURATION_MS);
}

async function copySelectedField(field, actionTarget = null) {
  if (!state.selectedEntry) {
    return;
  }

  const value = state.selectedEntry[field];
  if (!value) {
    return;
  }

  await withHandledError(async () => {
    await vaultApi.copyToClipboard(value, field === "password" ? state.selectedEntry.id : null);
    await handleClipboardCopy(actionTarget, clipboardLabelForField(field));
    if (field === "password") {
      state.selectedEntry.accessed_at = new Date().toISOString();
    }
  });
}

async function copyEntryPassword(entryId, actionTarget = null) {
  if (!entryId) {
    return;
  }

  await withHandledError(async () => {
    const entry =
      state.selectedEntry?.id === entryId ? state.selectedEntry : await vaultApi.getEntry(entryId);
    if (!entry?.password) {
      return;
    }

    await vaultApi.copyToClipboard(entry.password, entry.id);
    await handleClipboardCopy(actionTarget, t("common.password"));
    if (state.selectedEntry?.id === entryId) {
      state.selectedEntry.accessed_at = new Date().toISOString();
    }
  });
}

async function copyCustomField(index, actionTarget = null) {
  if (!state.selectedEntry) {
    return;
  }
  const value = state.selectedEntry.custom_fields?.[Number(index)]?.value;
  if (!value) {
    return;
  }
  await withHandledError(async () => {
    await vaultApi.copyToClipboard(value);
    await handleClipboardCopy(actionTarget, t("entry.customField"));
  });
}

function clipboardLabelForField(field) {
  switch (field) {
    case "password":
      return t("common.password");
    case "username":
      return t("common.usernameOrEmail");
    case "url":
      return t("common.url");
    default:
      return t("common.copy");
  }
}

function clearClipboardChoiceTimers() {
  if (clipboardChoiceDismissTimer) {
    clearTimeout(clipboardChoiceDismissTimer);
    clipboardChoiceDismissTimer = null;
  }
  if (clipboardChoiceTicker) {
    clearInterval(clipboardChoiceTicker);
    clipboardChoiceTicker = null;
  }
}

function clearClipboardChoice() {
  clearClipboardChoiceTimers();
  state.ui.clipboardChoice = null;
}

function resolveClipboardChoicePosition(actionTarget) {
  const frameRect =
    document.querySelector(".app-frame")?.getBoundingClientRect() || {
      left: 0,
      top: 0
    };
  if (!(actionTarget instanceof HTMLElement)) {
    return {
      left:
        Math.max(
          CLIPBOARD_POPUP_MARGIN_PX,
          Math.round(window.innerWidth / 2 - CLIPBOARD_POPUP_WIDTH_PX / 2)
        ) - frameRect.left,
      top:
        Math.max(
          CLIPBOARD_POPUP_MARGIN_PX,
          Math.round(window.innerHeight / 2 - CLIPBOARD_POPUP_FALLBACK_Y_PX)
        ) - frameRect.top
    };
  }

  const rect = actionTarget.getBoundingClientRect();
  const left = Math.max(
    CLIPBOARD_POPUP_MARGIN_PX,
    Math.min(
      Math.round(rect.left + rect.width / 2 - CLIPBOARD_POPUP_WIDTH_PX / 2),
      Math.max(
        CLIPBOARD_POPUP_MARGIN_PX,
        window.innerWidth - CLIPBOARD_POPUP_WIDTH_PX - CLIPBOARD_POPUP_MARGIN_PX
      )
    )
  );
  const top = Math.max(
    CLIPBOARD_POPUP_MARGIN_PX,
    Math.min(
      Math.round(rect.bottom + CLIPBOARD_POPUP_OFFSET_PX),
      window.innerHeight - CLIPBOARD_POPUP_MAX_TOP_PX
    )
  );
  return { left: left - frameRect.left, top: top - frameRect.top };
}

function promptClipboardChoice(actionTarget, label) {
  clearClipboardChoice();
  clearClipboardCountdown();

  state.ui.clipboardHasContent = true;
  state.ui.clipboardChoice = {
    label,
    mode: "timed",
    remember: false,
    timeoutSecs: currentClipboardTimeoutSecs(),
    remaining: CLIPBOARD_CHOICE_DISMISS_SECS,
    ...resolveClipboardChoicePosition(actionTarget)
  };
  render();

  clipboardChoiceTicker = setInterval(() => {
    if (!state.ui.clipboardChoice) {
      clearClipboardChoiceTimers();
      return;
    }
    state.ui.clipboardChoice.remaining = Math.max(0, state.ui.clipboardChoice.remaining - 1);
    updateClipboardChoiceDisplay();
  }, 1000);

  clipboardChoiceDismissTimer = setTimeout(() => {
    cancelClipboardChoice();
  }, CLIPBOARD_CHOICE_DISMISS_SECS * 1000);
}

function currentClipboardTimeoutSecs() {
  const timeoutSecs = Number(state.forms.settings.clipboard_timeout_secs);
  return [60, 300, 600, 1800].includes(timeoutSecs)
    ? timeoutSecs
    : DEFAULT_CLIPBOARD_TIMEOUT_SECS;
}

function normalizedClipboardMode(mode) {
  return mode === "manual" || mode === "never" ? "manual" : "timed";
}

function rememberedClipboardMode() {
  return normalizedClipboardMode(state.forms.settings.clipboard_mode);
}

async function handleClipboardCopy(actionTarget, label) {
  flashCopiedState(actionTarget);
  state.ui.clipboardHasContent = true;

  if (state.forms.settings.clipboard_remember_choice) {
    clearClipboardChoice();
    clearClipboardCountdown();
    patchClipboardState();
    await applyClipboardMode(rememberedClipboardMode(), currentClipboardTimeoutSecs());
    return;
  }

  promptClipboardChoice(actionTarget, label);
}

async function confirmClipboardChoice() {
  if (!state.ui.clipboardChoice) {
    return;
  }

  const { mode, remember, timeoutSecs } = state.ui.clipboardChoice;
  clearClipboardChoice();
  patchClipboardState();

  if (remember) {
    await withHandledError(async () => {
      const settings = await vaultApi.updateSettings({
        clipboard_mode: normalizedClipboardMode(mode),
        clipboard_timeout_secs: timeoutSecs,
        clipboard_remember_choice: true
      });
      syncSettingsForm(settings);
    });
  }

  await applyClipboardMode(mode, timeoutSecs);
}

async function applyClipboardMode(mode, timeoutSecs) {
  state.ui.clipboardHasContent = true;
  patchClipboardState();

  await withHandledError(async () => {
    if (normalizedClipboardMode(mode) !== "timed") {
      clearClipboardCountdown();
      patchClipboardState();
      return;
    }

    await vaultApi.scheduleClipboardClear(timeoutSecs);
    startClipboardCountdown(timeoutSecs);
  });
}

function cancelClipboardChoice() {
  if (!state.ui.clipboardChoice) {
    return;
  }

  clearClipboardChoice();
  clearClipboardCountdown();
  state.ui.clipboardHasContent = true;
  patchClipboardState();
}

async function resetClipboardPreference() {
  await withHandledError(async () => {
    const settings = await vaultApi.updateSettings({
      clipboard_remember_choice: false
    });
    syncSettingsForm(settings);
    toast(t("messages.clipboardPreferenceReset"));
    render();
  });
}

async function toggleEntryFavorite(entryId) {
  await withHandledError(async () => {
    const entry = state.selectedEntry?.id === entryId ? state.selectedEntry : await vaultApi.getEntry(entryId);
    await vaultApi.updateEntry(entryId, {
      title: entry.title,
      username: entry.username,
      password: entry.password,
      url: entry.url,
      notes: entry.notes,
      category_id: entry.category_id,
      tags: entry.tags || [],
      favorite: !entry.favorite,
      custom_fields: entry.custom_fields || []
    });
    await loadVaultData();
  });
}

function openConfirmDialog({
  kind,
  title,
  message,
  confirmLabel,
  url = null,
  entryId = null,
  categoryId = null
}) {
  state.forms.confirm = {
    open: true,
    kind,
    title,
    message,
    confirmLabel,
    url,
    entryId,
    categoryId
  };
  render();
}

async function runConfirmAction() {
  const { kind, url, entryId, categoryId } = state.forms.confirm;

  await withHandledError(async () => {
    switch (kind) {
      case "delete-entry":
        await vaultApi.deleteEntry(entryId);
        toast(t("messages.entryDeleted"));
        break;
      case "permanent-delete":
        await vaultApi.permanentDelete(entryId);
        toast(t("messages.entryRemoved"));
        break;
      case "delete-category":
        await vaultApi.deleteCategory(categoryId);
        if (state.filters.categoryId === categoryId) {
          state.filters.categoryId = "all";
        }
        toast(t("messages.categoryDeleted"));
        break;
      case "restore-backup":
        await vaultApi.restoreLastGoodBackup(state.forms.unlock.password);
        toast(t("vault.restoreBackupDone"));
        state.forms.confirm = emptyConfirmForm();
        await submitUnlock();
        return;
      case "open-url":
        await vaultApi.openUrl(url);
        break;
      default:
        break;
    }

    state.forms.confirm = emptyConfirmForm();
    if (kind === "delete-entry" || kind === "permanent-delete") {
      await loadVaultData();
    } else if (kind === "delete-category") {
      await loadVaultData();
    } else {
      render();
    }
  });
}

function flashCopiedState(button) {
  if (!button) {
    return;
  }

  const label = button.dataset.copiedLabel || t("common.copied");
  if (button._copyFeedbackTimer) {
    clearTimeout(button._copyFeedbackTimer);
    restoreCopiedState(button);
  }

  button._copyFeedbackNodes = Array.from(button.childNodes).map((node) => node.cloneNode(true));
  button.replaceChildren(document.createTextNode(`${label} ✓`));
  button.classList.add("is-copied");
  button._copyFeedbackTimer = setTimeout(() => {
    restoreCopiedState(button);
  }, COPY_FEEDBACK_DURATION_MS);
}

function restoreCopiedState(button) {
  if (!button) {
    return;
  }

  if (Array.isArray(button._copyFeedbackNodes)) {
    button.replaceChildren(...button._copyFeedbackNodes.map((node) => node.cloneNode(true)));
  }

  button.classList.remove("is-copied");
  button._copyFeedbackNodes = null;
  button._copyFeedbackTimer = null;
}

function previewImport(type, fileName, content) {
  const entries = parsePreviewEntries(type, content);
  const existingFingerprints = new Set(
    state.entries.map((entry) => fingerprint(entry.title, entry.username, entry.url))
  );
  const duplicates = entries
    .filter((entry) => existingFingerprints.has(fingerprint(entry.title, entry.username, entry.url)))
    .map((entry) => entry.title || entry.username || entry.url || "Untitled");

  return {
    fileName,
    count: entries.length,
    duplicates
  };
}

function parsePreviewEntries(type, content) {
  switch (type) {
    case "bitwarden":
      return parseBitwardenPreview(content);
    case "keepass":
      return parseKeepassPreview(content);
    default:
      return parseCsvPreview(content);
  }
}

function parseBitwardenPreview(content) {
  const parsed = JSON.parse(content);
  const items = parsed.items || [];
  return items.map((item) => ({
    title: item.name || "Untitled",
    username: item.login?.username || "",
    url: item.login?.uris?.[0]?.uri || ""
  }));
}

function parseKeepassPreview(content) {
  const xml = strictParseXmlDocument(content, "KeePassFile");
  const entryNodes = Array.from(xml.querySelectorAll("Entry"));
  return entryNodes.map((entryNode) => {
    const fields = Object.fromEntries(
      Array.from(entryNode.querySelectorAll("String")).map((node) => [
        node.querySelector("Key")?.textContent || "",
        node.querySelector("Value")?.textContent || ""
      ])
    );

    return {
      title: fields.Title || "Imported Entry",
      username: fields.UserName || "",
      url: fields.URL || ""
    };
  });
}

function strictParseXmlDocument(content, expectedRoot) {
  const xml = new DOMParser().parseFromString(content, "application/xml");
  if (xml.querySelector("parsererror")) {
    throw new Error(t("validation.invalidImport"));
  }

  const rootElement = xml.documentElement;
  if (!rootElement || rootElement.tagName !== expectedRoot) {
    throw new Error(t("validation.invalidImport"));
  }

  return xml;
}

function parseCsvPreview(content) {
  const rows = parseCsv(content);
  if (rows.length < 2) {
    return [];
  }

  const headers = rows[0].map((header) => header.toLowerCase());
  const titleIndex = findColumn(headers, ["name", "title", "entry", "site"]);
  const usernameIndex = findColumn(headers, ["username", "user", "email", "login"]);
  const urlIndex = findColumn(headers, ["url", "uri", "website", "site", "link"]);

  return rows.slice(1).map((row) => ({
    title: row[titleIndex] || "Imported Entry",
    username: row[usernameIndex] || "",
    url: row[urlIndex] || ""
  }));
}

function parseCsv(content) {
  const rows = [];
  let current = "";
  let row = [];
  let inQuotes = false;

  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    const next = content[index + 1];

    if (char === '"' && inQuotes && next === '"') {
      current += '"';
      index += 1;
      continue;
    }

    if (char === '"') {
      inQuotes = !inQuotes;
      continue;
    }

    if (char === "," && !inQuotes) {
      row.push(current);
      current = "";
      continue;
    }

    if ((char === "\n" || char === "\r") && !inQuotes) {
      if (char === "\r" && next === "\n") {
        index += 1;
      }
      row.push(current);
      if (row.some((cell) => cell.length > 0)) {
        rows.push(row);
      }
      row = [];
      current = "";
      continue;
    }

    current += char;
  }

  if (current.length || row.length) {
    row.push(current);
    rows.push(row);
  }

  return rows;
}

function findColumn(headers, matches) {
  return headers.findIndex((header) => matches.some((match) => header.includes(match)));
}

function fingerprint(title, username, url) {
  return [title || "", username || "", url || ""].join("::").toLowerCase();
}

function mapStrength(strength) {
  if (!strength) {
    return null;
  }
  const level = ["weak", "fair", "good", "strong"][strength.level] || "weak";
  return {
    width: [25, 50, 75, 100][strength.level] || 25,
    scoreLabel: t(`strength.${level}`),
    level,
    crackTime: strength.crack_time,
    entropyBits: strength.entropy_bits
  };
}

function scheduleStrengthUpdate(scope) {
  clearTimeout(strengthDebouncers.get(scope));
  strengthDebouncers.set(
    scope,
    setTimeout(async () => {
      const password = getPasswordForScope(scope);
      if (!password) {
        setStrengthForScope(scope, null);
        patchStrengthDisplay(scope);
        return;
      }

      try {
        const strength = await vaultApi.checkPasswordStrength(password);
        setStrengthForScope(scope, mapStrength(strength));
        patchStrengthDisplay(scope);
      } catch (error) {
        toast(error.message, "error");
      }
    }, 120)
  );
}

function getPasswordForScope(scope) {
  switch (scope) {
    case "setup":
      return state.forms.setup.password;
    case "entry":
      return state.forms.entry.draft.password;
    case "changePassword":
      return state.forms.changePassword.newPassword;
    default:
      return "";
  }
}

function setStrengthForScope(scope, value) {
  switch (scope) {
    case "setup":
      state.forms.setup.strength = value;
      break;
    case "entry":
      state.forms.entry.strength = value;
      break;
    case "changePassword":
      state.forms.changePassword.strength = value;
      break;
    default:
      break;
  }
}

function scheduleSecurityPolling() {
  clearSecurityPolling();
  securityPoller = setInterval(async () => {
    if (!state.unlocked) {
      return;
    }

    try {
      state.securityStatus = await vaultApi.getVaultFileStatus();
      if (state.securityStatus.modified_externally) {
        await performLock(t("messages.vaultModifiedLocked"));
        return;
      }
    } catch {
      // The vault may already be locking; ignore transient polling failures.
    }
  }, SECURITY_POLL_INTERVAL_MS);
}

function clearSecurityPolling() {
  if (securityPoller) {
    clearInterval(securityPoller);
    securityPoller = null;
  }
}

function startClipboardCountdown(seconds) {
  clearClipboardCountdown();
  const expiresAt = Date.now() + seconds * 1000;
  state.ui.clipboardCountdown = { remaining: seconds, expiresAt };
  state.ui.clipboardHasContent = true;
  patchClipboardState();
  updateClipboardCountdownDisplay();

  clipboardTicker = setInterval(() => {
    const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    if (!state.ui.clipboardCountdown) {
      clearClipboardCountdown();
      return;
    }
    state.ui.clipboardCountdown.remaining = remaining;
    if (remaining <= 0) {
      clearClipboardCountdown();
      return;
    }
    updateClipboardCountdownDisplay();
  }, 1000);
}

function clearClipboardCountdown() {
  const hadCountdown = Boolean(state.ui.clipboardCountdown);
  if (clipboardTicker) {
    clearInterval(clipboardTicker);
    clipboardTicker = null;
  }
  state.ui.clipboardCountdown = null;
  if (hadCountdown) {
    patchClipboardState();
  }
  updateClipboardCountdownDisplay();
}

function resetAutoLockTimer() {
  if (!state.unlocked) {
    return;
  }

  clearAutoLockTimer();
  const minutes = Number(state.forms.settings.auto_lock_minutes);
  if (!minutes) {
    return;
  }

  autoLockTimer = setTimeout(async () => {
    await performLock(t("messages.vaultLocked"));
  }, minutes * 60 * 1000);
}

function clearAutoLockTimer() {
  if (autoLockTimer) {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
  }
}

function getInputValue(element) {
  return element.type === "checkbox" ? element.checked : element.value;
}

function resetSetupForm() {
  state.forms.setup = {
    password: "",
    confirmPassword: "",
    showPassword: false,
    showConfirmPassword: false,
    strength: null
  };
}

function emptySetupConfirmationForm() {
  return {
    stage: null,
    readyChecked: false
  };
}

function emptyChangePasswordForm() {
  return {
    open: false,
    currentPassword: "",
    newPassword: "",
    confirmNewPassword: "",
    strength: null
  };
}

function emptyMasterPasswordPromptForm() {
  return {
    open: false,
    password: "",
    resumeSettingsSection: "data"
  };
}

function syncSettingsForm(settings, options = {}) {
  state.forms.settings = {
    open: options.open ?? state.forms.settings.open,
    auto_lock_minutes: settings.auto_lock_minutes,
    clipboard_mode: normalizedClipboardMode(settings.clipboard_mode),
    clipboard_timeout_secs: Number(settings.clipboard_timeout_secs) || DEFAULT_CLIPBOARD_TIMEOUT_SECS,
    clipboard_remember_choice: Boolean(settings.clipboard_remember_choice),
    language: settings.language,
    theme: state.ui.theme,
    expanded_section: (options.expandedSection ?? state.forms.settings.expanded_section) || "general"
  };
}

function emptyConfirmForm() {
  return {
    open: false,
    kind: null,
    title: "",
    message: "",
    confirmLabel: "",
    url: null,
    entryId: null,
    categoryId: null
  };
}

function toast(message, tone = "info") {
  state.toasts.push({
    id: crypto.randomUUID(),
    message,
    tone
  });
  patchToastLayer();

  setTimeout(() => {
    state.toasts = state.toasts.slice(1);
    patchToastLayer();
  }, TOAST_DURATION_MS);
}

async function withHandledError(task, onError = null) {
  try {
    await task();
  } catch (error) {
    if (onError) {
      onError(error);
    }
    state.bruteForceStatus = state.vaultExists ? await safeBruteForceStatus() : null;
    syncLockoutTicker();
    toast(error.message, "error");
    if (!state.unlocked) {
      render();
    }
  }
}

async function safeBruteForceStatus() {
  try {
    return await vaultApi.getBruteForceStatus();
  } catch {
    return state.bruteForceStatus;
  }
}

async function animateLockButtonAndLock(button) {
  if (!button) {
    await performLock(t("messages.vaultLocked"));
    return;
  }

  button.classList.add("is-pulsing");
  await new Promise((resolve) => setTimeout(resolve, 200));
  button.classList.remove("is-pulsing");
  await performLock(t("messages.vaultLocked"));
}

function downloadText(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function throttle(fn, wait) {
  let lastCall = 0;
  return (...args) => {
    const now = Date.now();
    if (now - lastCall >= wait) {
      lastCall = now;
      fn(...args);
    }
  };
}
