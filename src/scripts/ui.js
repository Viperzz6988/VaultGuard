import { escapeHtml, highlightText } from "/scripts/search.js";

const LOGO_SRC = "/assets/VaultGuardV3.png";
const CATEGORY_EMOJI_CHOICES = [
  "🔑",
  "🔐",
  "📁",
  "💳",
  "🌐",
  "🔒",
  "⚡",
  "🏦",
  "🛡",
  "📧",
  "🎮",
  "💼",
  "🔧",
  "🖥",
  "📱",
  "🌟",
  "💡",
  "🎵",
  "📂",
  "🗂"
];

function renderCopyIcon() {
  return `
    <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
      <path d="M9 9.75A2.25 2.25 0 0 1 11.25 7.5h6A2.25 2.25 0 0 1 19.5 9.75v8.25A2.25 2.25 0 0 1 17.25 20.25h-6A2.25 2.25 0 0 1 9 18Z" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linejoin="round"/>
      <path d="M6.75 15.75A2.25 2.25 0 0 1 4.5 13.5V5.25A2.25 2.25 0 0 1 6.75 3h6.75A2.25 2.25 0 0 1 15.75 5.25" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/>
    </svg>
  `;
}

function renderThemeIcon(theme) {
  if (theme === "light") {
    return `
      <svg viewBox="0 0 24 24" width="20" height="20" focusable="false" aria-hidden="true">
        <path d="M12 5V3.5M12 20.5V19M5 12H3.5M20.5 12H19M6.7 6.7 5.6 5.6M18.4 18.4l-1.1-1.1M17.3 6.7l1.1-1.1M5.6 18.4l1.1-1.1" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        <circle cx="12" cy="12" r="4.2" fill="none" stroke="currentColor" stroke-width="1.8"/>
      </svg>
    `;
  }

  return `
    <svg viewBox="0 0 24 24" width="20" height="20" focusable="false" aria-hidden="true">
      <path d="M16.75 3.25a7.75 7.75 0 1 0 4 14.39A8.75 8.75 0 0 1 16.75 3.25Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
    </svg>
  `;
}

function renderLockIcon() {
  return `
    <svg viewBox="0 0 24 24" width="20" height="20" focusable="false" aria-hidden="true">
      <path d="M8 10.25V8.5a4 4 0 1 1 8 0v1.75" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      <rect x="5.75" y="10.25" width="12.5" height="10" rx="2.4" fill="currentColor"/>
    </svg>
  `;
}

function renderSettingsIcon() {
  return `
    <svg viewBox="0 0 24 24" width="20" height="20" focusable="false" aria-hidden="true">
      <path d="M10.2 3.8h3.6l.65 2.25a6.99 6.99 0 0 1 1.64.95l2.14-.92 1.8 3.12-1.5 1.75c.08.35.12.7.12 1.05s-.04.7-.12 1.05l1.5 1.75-1.8 3.12-2.14-.92c-.5.39-1.06.71-1.64.95l-.65 2.25h-3.6l-.65-2.25a6.99 6.99 0 0 1-1.64-.95l-2.14.92-1.8-3.12 1.5-1.75a4.95 4.95 0 0 1 0-2.1l-1.5-1.75 1.8-3.12 2.14.92c.5-.39 1.06-.71 1.64-.95Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
      <circle cx="12" cy="12" r="2.8" fill="none" stroke="currentColor" stroke-width="1.6"/>
    </svg>
  `;
}

function renderPlusIcon() {
  return `
    <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
      <path d="M12 5v14M5 12h14" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>
    </svg>
  `;
}

function renderTrashIcon() {
  return `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" focusable="false" aria-hidden="true">
      <polyline points="3 6 5 6 21 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></polyline>
      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
      <path d="M10 11v6M14 11v6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
      <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>
  `;
}

function renderDragHandleIcon() {
  return `
    <svg viewBox="0 0 20 20" focusable="false" aria-hidden="true">
      <circle cx="7" cy="5" r="1.1" fill="currentColor" />
      <circle cx="7" cy="10" r="1.1" fill="currentColor" />
      <circle cx="7" cy="15" r="1.1" fill="currentColor" />
      <circle cx="13" cy="5" r="1.1" fill="currentColor" />
      <circle cx="13" cy="10" r="1.1" fill="currentColor" />
      <circle cx="13" cy="15" r="1.1" fill="currentColor" />
    </svg>
  `;
}

function renderEyeIcon(visible) {
  if (visible) {
    return `
      <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
        <path d="M3.75 3.75 20.25 20.25M9.88 9.88A3 3 0 0 0 14.12 14.12M6.42 6.42C4.68 7.73 3.55 9.42 3 12c1.22 3.56 4.58 6 9 6 1.88 0 3.57-.44 5.02-1.22M17.56 17.56C19.32 16.25 20.45 14.56 21 12c-1.22-3.56-4.58-6-9-6-1.12 0-2.19.16-3.2.47" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `;
  }

  return `
    <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
      <path d="M3 12c1.22-3.56 4.58-6 9-6s7.78 2.44 9 6c-1.22 3.56-4.58 6-9 6S4.22 15.56 3 12Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/>
      <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.7"/>
    </svg>
  `;
}

function renderChevronIcon() {
  return `
    <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
      <path d="m9 6 6 6-6 6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  `;
}

function renderCategoryDot(color) {
  return `
    <span class="category-dot" aria-hidden="true">
      <svg viewBox="0 0 12 12" focusable="false" aria-hidden="true">
        <circle cx="6" cy="6" r="5" fill="${escapeHtml(color || "currentColor")}" />
      </svg>
    </span>
  `;
}

function renderStrengthLegend(level) {
  return `
    <div class="strength-meter" aria-hidden="true">
      <span data-strength-fill data-level="${escapeHtml(level || "none")}"></span>
    </div>
  `;
}

function renderStrengthBlock(strength, t, fallback = "—", scope = "") {
  return `
    <div class="strength-block" ${scope ? `data-strength-scope="${escapeHtml(scope)}"` : ""}>
      <div class="strength-header">
        <span>${escapeHtml(t("entry.strength"))}</span>
        <strong data-strength-label>${escapeHtml(strength?.scoreLabel || "—")}</strong>
      </div>
      ${renderStrengthLegend(strength?.level || "none")}
      <div class="strength-meta">
        <span data-strength-meta>${
          escapeHtml(
            strength?.crackTime ? `${t("entry.crackTime")}: ${strength.crackTime}` : fallback
          )
        }</span>
      </div>
    </div>
  `;
}

function renderEmptyState(icon, title, body, actionMarkup = "") {
  return `
    <div class="empty-state">
      <div class="empty-state-icon" aria-hidden="true">${icon}</div>
      <h2>${escapeHtml(title)}</h2>
      <p>${escapeHtml(body)}</p>
      ${actionMarkup}
    </div>
  `;
}

function renderLoadingShell() {
  return `
    <main class="screen screen-centered boot-screen">
      <div class="boot-card">
        <img class="boot-logo" src="${LOGO_SRC}" alt="" />
      </div>
    </main>
  `;
}

function renderStartupIntro(content) {
  return `
    <div
      id="startup-overlay"
      data-startup-overlay
      data-action="skip-startup-intro"
      role="button"
      tabindex="0"
      aria-label="Skip intro"
    >
      <div class="startup-content" data-startup-content>${content}</div>
      <div id="startup-wrapper">
        <div id="vault-flash" aria-hidden="true"></div>
        <img id="startup-icon" src="${LOGO_SRC}" alt="" />
      </div>
    </div>
  `;
}

function renderPostLoginLoading(t) {
  return `
    <main class="screen screen-centered decrypt-screen">
      <section class="decrypt-card fade-in-up">
        <img class="decrypt-logo" src="${LOGO_SRC}" alt="" />
        <h1>${escapeHtml(t("app.name"))}</h1>
        <div class="loading-progress" aria-hidden="true">
          <span class="loading-progress-fill"></span>
        </div>
      </section>
    </main>
  `;
}

function renderPasswordInput({
  inputId,
  placeholder,
  value,
  visible,
  model,
  autocomplete,
  toggleAction
}) {
  return `
    <div class="input-shell">
      <input
        id="${escapeHtml(inputId)}"
        type="${visible ? "text" : "password"}"
        placeholder="${escapeHtml(placeholder)}"
        value="${escapeHtml(value)}"
        data-model="${escapeHtml(model)}"
        autocomplete="${escapeHtml(autocomplete)}"
        aria-label="${escapeHtml(placeholder)}"
        required
      />
      <button
        class="field-toggle-button"
        type="button"
        data-action="${escapeHtml(toggleAction)}"
        aria-label="${visible ? "Hide password" : "Show password"}"
      >
        ${renderEyeIcon(visible)}
      </button>
    </div>
  `;
}

function masterPasswordChecklist(password, t) {
  const characters = Array.from(password || "");
  const checks = [
    {
      met: characters.length >= 15,
      label: t("setup.requirements.length")
    },
    {
      met: /[A-Z]/.test(password),
      label: t("setup.requirements.uppercase")
    },
    {
      met: /[a-z]/.test(password),
      label: t("setup.requirements.lowercase")
    },
    {
      met: /\d/.test(password),
      label: t("setup.requirements.number")
    },
    {
      met: /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(password),
      label: t("setup.requirements.special")
    }
  ];

  return {
    checks,
    allMet: checks.every((check) => check.met)
  };
}

function renderSetupScreen(state, t) {
  const checklist = masterPasswordChecklist(state.forms.setup.password, t);

  return `
    <main class="screen screen-centered auth-screen">
      <section class="auth-card auth-card-minimal fade-in-up">
        <img class="auth-logo auth-logo-large" src="${LOGO_SRC}" alt="" />
        <h1>${escapeHtml(t("setup.title"))}</h1>

        <form class="stack-form" data-form="setup">
          ${renderPasswordInput({
            inputId: "setup-password",
            placeholder: t("setup.masterPassword"),
            value: state.forms.setup.password,
            visible: Boolean(state.forms.setup.showPassword),
            model: "setup.password",
            autocomplete: "new-password",
            toggleAction: "toggle-setup-password"
          })}

          ${renderPasswordInput({
            inputId: "setup-confirm-password",
            placeholder: t("setup.confirmPassword"),
            value: state.forms.setup.confirmPassword,
            visible: Boolean(state.forms.setup.showConfirmPassword),
            model: "setup.confirmPassword",
            autocomplete: "new-password",
            toggleAction: "toggle-setup-confirm-password"
          })}

          <ul class="password-checklist" aria-live="polite">
            ${checklist.checks
              .map(
                (check) => `
                  <li class="password-checklist-item ${check.met ? "is-met" : "is-unmet"}">
                    <span aria-hidden="true">${check.met ? "✓" : "✗"}</span>
                    <span>${escapeHtml(check.label)}</span>
                  </li>
                `
              )
              .join("")}
          </ul>

          <button class="primary-button auth-submit-button" type="submit" ${checklist.allMet ? "" : "disabled"}>
            ${escapeHtml(t("setup.createVault"))}
          </button>

          <p class="auth-warning">
            ${escapeHtml(t("setup.warningLead"))}
            <strong>${escapeHtml(t("setup.warningNeverStored"))}</strong>
            ${escapeHtml(t("setup.warningMiddle"))}
            <strong>${escapeHtml(t("setup.warningCannotRecover"))}</strong>
            ${escapeHtml(t("setup.warningTail"))}
          </p>
        </form>
      </section>
    </main>
  `;
}

function renderSetupWarningScreen(t) {
  return `
    <main class="screen screen-centered auth-screen">
      <section class="auth-card auth-card-minimal onboarding-card fade-in-up">
        <div class="onboarding-icon" aria-hidden="true">⚠</div>
        <h1>${escapeHtml(t("setup.confirmationWarningTitle"))}</h1>
        <p class="onboarding-copy">${escapeHtml(t("setup.confirmationWarningBody"))}</p>
        <ul class="onboarding-list">
          <li>${escapeHtml(t("setup.confirmationWarningLoss1"))}</li>
          <li>${escapeHtml(t("setup.confirmationWarningLoss2"))}</li>
          <li>${escapeHtml(t("setup.confirmationWarningLoss3"))}</li>
        </ul>
        <p class="onboarding-copy">${escapeHtml(t("setup.confirmationWarningFooter"))}</p>
        <button class="primary-button auth-submit-button" type="button" data-action="acknowledge-master-password-warning">
          ${escapeHtml(t("setup.confirmationWarningAction"))}
        </button>
      </section>
    </main>
  `;
}

function renderSetupReadyScreen(state, t) {
  return `
    <main class="screen screen-centered auth-screen">
      <section class="auth-card auth-card-minimal onboarding-card fade-in-up">
        <h1>${escapeHtml(t("setup.confirmationReadyTitle"))}</h1>
        <label class="checkbox-row onboarding-checkbox">
          <input
            type="checkbox"
            data-model="setupConfirmation.readyChecked"
            ${state.forms.setupConfirmation.readyChecked ? "checked" : ""}
          />
          <span>${escapeHtml(t("setup.confirmationReadyCheckbox"))}</span>
        </label>
        <footer class="modal-actions onboarding-actions">
          <button class="ghost-button" type="button" data-action="cancel-master-password-confirmation">
            ${escapeHtml(t("common.cancel"))}
          </button>
          <button
            class="primary-button"
            type="button"
            data-action="finish-master-password-confirmation"
            ${state.forms.setupConfirmation.readyChecked ? "" : "disabled"}
          >
            ${escapeHtml(t("setup.confirmationReadyAction"))}
          </button>
        </footer>
      </section>
    </main>
  `;
}

function renderSetupIntegrityScreen(t) {
  return `
    <main class="screen screen-centered auth-screen">
      <section class="auth-card auth-card-minimal onboarding-card fade-in-up">
        <div class="onboarding-icon" aria-hidden="true">🛡</div>
        <h1>${escapeHtml(t("setup.integrityTitle"))}</h1>
        <p class="onboarding-copy">${escapeHtml(t("setup.integrityBody"))}</p>
        <p class="onboarding-copy">${escapeHtml(t("setup.integrityRecommendation"))}</p>
        <footer class="modal-actions onboarding-actions">
          <button class="ghost-button" type="button" data-action="skip-integrity-protection">
            ${escapeHtml(t("setup.integritySkip"))}
          </button>
          <button class="primary-button" type="button" data-action="enable-integrity-protection">
            ${escapeHtml(t("setup.integrityEnable"))}
          </button>
        </footer>
      </section>
    </main>
  `;
}

function renderIntegrityAlertScreen(state, t) {
  return `
    <main class="screen screen-centered auth-screen">
      <section class="auth-card auth-card-minimal onboarding-card fade-in-up">
        <div class="onboarding-icon onboarding-icon-danger" aria-hidden="true">⛔</div>
        <h1>${escapeHtml(t("security.integrityAlertTitle"))}</h1>
        <p class="onboarding-copy">${escapeHtml(t("security.integrityAlertBody"))}</p>
        <div class="onboarding-list onboarding-list-alert">
          <p>${escapeHtml(state.ui.startupIntegrityAlert || t("security.integrityAlertBody"))}</p>
        </div>
        <button class="danger-button auth-submit-button" type="button" data-action="exit-app">
          ${escapeHtml(t("security.integrityAlertExit"))}
        </button>
      </section>
    </main>
  `;
}

function formatLockoutCountdown(seconds) {
  const totalSeconds = Math.max(0, Number(seconds) || 0);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (hours > 0) {
    return `${hours} ${hours === 1 ? "hour" : "hours"} ${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
  }
  return `${minutes} ${minutes === 1 ? "minute" : "minutes"}`;
}

function renderUnlockScreen(state, t) {
  const status = state.bruteForceStatus || {};

  if (status.is_locked_out) {
    return `
      <main class="screen screen-centered auth-screen">
        <section class="auth-card auth-card-minimal auth-lockout-card fade-in-up">
          <img class="auth-logo auth-logo-large" src="${LOGO_SRC}" alt="" />
          <h1>${escapeHtml(t("unlock.vaultLockedTitle"))}</h1>
          <p class="lockout-label">${escapeHtml(t("unlock.unlockingAvailable"))}</p>
          <div class="lockout-countdown" data-lockout-countdown>
            ${escapeHtml(formatLockoutCountdown(status.lockout_remaining_secs))}
          </div>
          <p class="auth-attempts">
            ${escapeHtml(t("unlock.securityLevel", { level: Math.max(1, status.lockout_tier || 1) }))}
          </p>
        </section>
      </main>
    `;
  }

  const failedAttempts = Number(status.failed_attempts || 0);

  return `
    <main class="screen screen-centered auth-screen">
      <section class="auth-card auth-card-minimal ${state.ui.unlockShake ? "shake-card" : ""}">
        <img class="auth-logo auth-logo-large" src="${LOGO_SRC}" alt="" />
        <h1>${escapeHtml(t("unlock.title"))}</h1>

        <form class="stack-form" data-form="unlock">
          ${renderPasswordInput({
            inputId: "unlock-password",
            placeholder: t("unlock.masterPassword"),
            value: state.forms.unlock.password,
            visible: Boolean(state.forms.unlock.showPassword),
            model: "unlock.password",
            autocomplete: "current-password",
            toggleAction: "toggle-unlock-password"
          })}

          <button class="primary-button auth-submit-button" type="submit">
            ${escapeHtml(t("unlock.unlockButton"))}
          </button>

          ${
            failedAttempts > 0
              ? `<p class="auth-attempts">${escapeHtml(t("unlock.failedAttempts", { count: failedAttempts }))}</p>`
              : ""
          }
        </form>
      </section>
    </main>
  `;
}

function renderVaultScreen(state, derived, t) {
  return `
    <main class="workspace-shell">
      ${renderSidebar(state, derived, t)}
      <section class="workspace-main">
        ${renderToolbar(state, derived, t)}
        <div class="workspace-columns">
          <section class="panel panel-list">
            ${renderEntryList(state, derived, t)}
          </section>
          <aside class="panel panel-detail ${derived.selectedRecord ? "detail-open" : ""}">
            ${renderDetailPanel(state, derived, t)}
          </aside>
        </div>
      </section>
      ${renderModals(state, derived, t)}
    </main>
  `;
}

function renderSidebar(state, derived, t) {
  const countByCategory = new Map();
  for (const entry of state.entries) {
    const key = entry.category_id || "builtin-other";
    countByCategory.set(key, (countByCategory.get(key) || 0) + 1);
  }

  const builtins = derived.categories.filter((category) => category.built_in);
  const customs = derived.categories.filter((category) => !category.built_in);
  const selectedCustomCategory =
    state.view === "entries"
      ? customs.find((category) => category.id === state.filters.categoryId) || null
      : null;

  const categoryRows = [...builtins, ...customs]
    .map((category) => renderCategoryRow(category, countByCategory.get(category.id) || 0, state, t))
    .join("");

  return `
    <nav class="workspace-sidebar sidebar" aria-label="${escapeHtml(t("common.categories"))}">
      <div class="sidebar-section">
        <div class="sidebar-section-header">${escapeHtml(t("vault.allItemsLabel"))}</div>
        <button
          class="sidebar-item ${state.view === "entries" && state.filters.categoryId === "all" ? "active" : ""}"
          type="button"
          data-action="show-all"
        >
          <span class="sidebar-item-icon" aria-hidden="true">○</span>
          <span class="sidebar-item-label">${escapeHtml(t("vault.allItems"))}</span>
          <span class="sidebar-count">${derived.entryCount}</span>
        </button>
        <button
          class="sidebar-item ${state.view === "trash" ? "active" : ""}"
          type="button"
          data-action="show-trash"
        >
          <span class="sidebar-item-icon" aria-hidden="true">🗑</span>
          <span class="sidebar-item-label">${escapeHtml(t("vault.trash"))}</span>
          <span class="sidebar-count">${derived.trashEntries.length}</span>
        </button>
      </div>

      <div class="sidebar-divider" aria-hidden="true"></div>

      <div class="sidebar-section sidebar-categories">
        <div class="sidebar-section-header">
          <span>${escapeHtml(t("common.categories"))}</span>
          <div class="sidebar-header-btns">
            <button
              id="add-cat-btn"
              class="sidebar-header-btn"
              type="button"
              data-action="${state.forms.category.open ? "close-category-popover" : "open-category-popover"}"
              aria-label="${escapeHtml(t("vault.newCategory"))}"
              title="${escapeHtml(t("vault.newCategory"))}"
            >
              ${renderPlusIcon()}
            </button>
            <button
              id="del-cat-btn"
              class="sidebar-header-btn"
              type="button"
              data-action="delete-category"
              ${selectedCustomCategory ? `data-category-id="${escapeHtml(selectedCustomCategory.id)}"` : ""}
              aria-label="${escapeHtml(t("common.delete"))}"
              title="${escapeHtml(t("common.delete"))}"
              ${selectedCustomCategory ? "" : "disabled"}
            >
              ${renderTrashIcon()}
            </button>
          </div>
        </div>
        ${categoryRows}
        ${state.forms.category.open ? renderCategoryPopover(state, t) : ""}
      </div>
    </nav>
  `;
}

function renderCategoryPopover(state, t) {
  const selectedEmoji = state.forms.category.draft.emoji || "📁";

  return `
    <div class="category-popover" role="dialog" aria-label="${escapeHtml(t("vault.newCategory"))}">
      <form class="category-popover-form" data-form="category">
        <div class="category-popover-title">${escapeHtml(t("vault.newCategory"))}</div>

        <label class="field">
          <span>${escapeHtml(t("category.name"))}</span>
          <input
            type="text"
            value="${escapeHtml(state.forms.category.draft.name)}"
            data-model="category.name"
            maxlength="64"
            placeholder="${escapeHtml(t("category.name"))}"
            aria-label="${escapeHtml(t("category.name"))}"
            required
          />
        </label>

        <div class="field">
          <span>${escapeHtml(t("category.emoji"))}</span>
          <div class="category-emoji-grid">
            ${CATEGORY_EMOJI_CHOICES.map(
              (emoji) => `
                <button
                  class="category-emoji-option ${selectedEmoji === emoji ? "is-selected" : ""}"
                  type="button"
                  data-action="select-category-emoji"
                  data-emoji="${escapeHtml(emoji)}"
                  aria-label="${escapeHtml(emoji)}"
                >
                  ${escapeHtml(emoji)}
                </button>
              `
            ).join("")}
          </div>
        </div>

        <label class="field">
          <span>${escapeHtml(t("category.orTypeEmoji"))}</span>
          <input
            type="text"
            value="${escapeHtml(state.forms.category.draft.emoji)}"
            data-model="category.emoji"
            maxlength="4"
            placeholder="📁"
            aria-label="${escapeHtml(t("category.emoji"))}"
          />
        </label>

        <footer class="modal-actions">
          <button class="ghost-button" type="button" data-action="close-category-popover">${escapeHtml(t("common.cancel"))}</button>
          <button class="primary-button" type="submit">${escapeHtml(t("common.create"))}</button>
        </footer>
      </form>
    </div>
  `;
}

function renderCategoryRow(category, count, state, t) {
  const isActive = state.view === "entries" && state.filters.categoryId === category.id;
  return `
    <button
      class="sidebar-item ${isActive ? "active" : ""}"
      type="button"
      data-action="filter-category"
      data-category-id="${escapeHtml(category.id)}"
      data-drop-category-id="${escapeHtml(category.id)}"
    >
      <span class="sidebar-item-icon" aria-hidden="true">${escapeHtml(category.emoji)}</span>
      <span class="sidebar-item-label">${escapeHtml(category.name)}</span>
      <span class="sidebar-count">${count}</span>
    </button>
  `;
}

function renderToolbar(state, derived, t) {
  const categories = derived.categories
    .map(
      (category) =>
        `<option value="${escapeHtml(category.id)}" ${state.filters.categoryId === category.id ? "selected" : ""}>${escapeHtml(category.name)}</option>`
    )
    .join("");

  return `
    <header class="toolbar">
      <div class="toolbar-brand">
        <img class="top-bar-icon" src="${LOGO_SRC}" alt="" />
        <strong class="top-bar-title">${escapeHtml(t("app.name"))}</strong>
      </div>

      <div class="toolbar-center">
        <div class="toolbar-search-group">
          <input
            id="vault-search"
            type="search"
            value="${escapeHtml(state.filters.query)}"
            data-model="filters.query"
            placeholder="${escapeHtml(t("vault.searchPlaceholder"))}"
            autocomplete="off"
          />
          <select data-model="filters.categoryId" ${state.view === "trash" ? "disabled" : ""}>
            <option value="all">${escapeHtml(t("common.all"))}</option>
            ${categories}
          </select>
        </div>
      </div>

      <div class="toolbar-actions">
        <button class="primary-button toolbar-new-entry" type="button" data-action="open-entry-modal">
          ${renderPlusIcon()}
          <span>${escapeHtml(t("vault.newEntry"))}</span>
        </button>
        <button
          class="ghost-button toolbar-clear-clipboard ${state.ui.clipboardHasContent && !state.ui.clipboardCountdown ? "is-attention" : ""}"
          type="button"
          data-action="clear-clipboard"
          ${state.ui.clipboardHasContent ? "" : "disabled"}
        >
          ${renderTrashIcon()}
          <span>${escapeHtml(t("common.clearClipboard"))}</span>
        </button>
        <button
          class="ghost-icon-button toolbar-lock-button"
          type="button"
          data-action="lock-vault"
          title="${escapeHtml(t("common.lockVault"))}"
          aria-label="${escapeHtml(t("common.lockVault"))}"
        >
          ${renderLockIcon()}
        </button>
        <button
          class="ghost-icon-button toolbar-settings-button"
          type="button"
          data-action="open-settings-modal"
          title="${escapeHtml(t("common.settings"))}"
          aria-label="${escapeHtml(t("common.settings"))}"
        >
          ${renderSettingsIcon()}
        </button>
        <button
          class="ghost-icon-button toolbar-theme-button"
          type="button"
          data-action="toggle-theme"
          title="${escapeHtml(t("common.toggleTheme"))}"
          aria-label="${escapeHtml(t("common.toggleTheme"))}"
        >
          ${renderThemeIcon(state.ui.theme)}
        </button>
      </div>
    </header>
  `;
}

export function renderEntryList(state, derived, t) {
  if (state.view === "trash") {
    if (derived.trashEntries.length === 0) {
      return renderEmptyState(
        `<img class="empty-icon-logo" src="${LOGO_SRC}" alt="" />`,
        t("trash.title"),
        t("trash.empty"),
        `<button class="ghost-button" type="button" data-action="show-all">${escapeHtml(t("vault.allItems"))}</button>`
      );
    }

    return `
      <div class="panel-header">
        <div>
          <h2>${escapeHtml(t("trash.title"))}</h2>
          <p>${escapeHtml(t("trash.recoveryHint"))}</p>
        </div>
      </div>
      <div class="entry-stack">
        ${derived.trashEntries
          .map((item) => {
            const isSelected = state.selectedEntryId === item.entry.id;
            return `
              <button class="entry-card entry-card-trash ${isSelected ? "is-selected" : ""}" type="button" data-action="select-trash-entry" data-entry-id="${escapeHtml(item.entry.id)}">
                <span class="entry-card-accent" aria-hidden="true"></span>
                <div class="entry-card-copy">
                  <h3>${escapeHtml(item.entry.title)}</h3>
                  <p>${escapeHtml(item.entry.username || item.entry.url || t("vault.trash"))}</p>
                </div>
              </button>
            `;
          })
          .join("")}
      </div>
    `;
  }

  if (derived.visibleEntries.length === 0) {
    const hasSearch = Boolean(String(state.filters.query || "").trim());
    return derived.entryCount === 0
      ? renderEmptyState(
          `<img class="empty-icon-logo" src="${LOGO_SRC}" alt="" />`,
          t("vault.emptyTitle"),
          t("vault.emptyBody"),
          `<button class="primary-button" type="button" data-action="open-entry-modal">${escapeHtml(t("vault.newEntry"))}</button>`
        )
      : hasSearch
        ? renderEmptyState(
          `<span class="empty-search-icon" aria-hidden="true">⌕</span>`,
          t("vault.noResults"),
          t("search.noMatches"),
          `<button class="ghost-button" type="button" data-action="reset-filters">${escapeHtml(t("common.clear"))}</button>`
        )
        : `
          <div class="detail-empty entry-list-empty-state">
            <img class="detail-empty-logo entry-list-empty-icon" src="${LOGO_SRC}" alt="" />
            <p>${escapeHtml(t("vault.noEntries"))}</p>
          </div>
        `;
  }

  return `
    <div class="panel-header">
      <div>
        <h2>${escapeHtml(derived.heading)}</h2>
        <p>${escapeHtml(t("vault.filteredEntriesCount", { visible: derived.visibleEntries.length, total: derived.entryCount }))}</p>
      </div>
    </div>

    <div class="entry-stack">
      ${renderEntryListCards(state, derived, t)}
    </div>
  `;
}

function renderEntryListCards(state, derived, t) {
  return derived.visibleEntries
    .map(({ entry }) =>
      renderEntryCard(
        entry,
        state.selectedEntryId === entry.id,
        derived.categoryById,
        state.filters.query,
        t
      )
    )
    .join("");
}

function renderEntryCard(entry, selected, categoryById, query, t) {
  const category = categoryById[entry.category_id] || null;
  const title = highlightText(entry.title, query);
  const subtitle =
    highlightText(entry.username || entry.url || "", query) || escapeHtml(t("common.usernameOrEmail"));

  return `
    <article
      class="entry-card-shell ${selected ? "is-selected" : ""}"
      draggable="true"
      data-draggable-entry="${escapeHtml(entry.id)}"
      data-reorder-entry-id="${escapeHtml(entry.id)}"
      data-entry-id="${escapeHtml(entry.id)}"
      data-entry-category-id="${escapeHtml(entry.category_id || "builtin-other")}"
    >
      <span class="entry-card-accent" aria-hidden="true">
        <svg viewBox="0 0 4 48" preserveAspectRatio="none" focusable="false" aria-hidden="true">
          <rect width="4" height="48" rx="2" fill="${escapeHtml(category?.color || "currentColor")}" />
        </svg>
      </span>
      <button class="entry-card" type="button" data-action="select-entry" data-entry-id="${escapeHtml(entry.id)}">
        <div class="entry-card-copy">
          <h3>${title}</h3>
          <p>${subtitle}</p>
        </div>
      </button>
      <span class="entry-drag-handle" aria-hidden="true">
        ${renderDragHandleIcon()}
      </span>
      <button
        class="ghost-icon-button entry-copy-button"
        type="button"
        data-action="copy-entry-password"
        data-entry-id="${escapeHtml(entry.id)}"
        aria-label="${escapeHtml(t("entry.copyPassword"))}"
      >
        ${renderCopyIcon()}
      </button>
    </article>
  `;
}

function renderDetailEmptyState(t) {
  return `
    <div class="detail-empty">
      <img class="detail-empty-logo" src="${LOGO_SRC}" alt="" />
      <p>${escapeHtml(t("vault.noSelection"))}</p>
    </div>
  `;
}

export function renderDetailPanel(state, derived, t) {
  if (state.view === "trash") {
    const record = derived.selectedRecord;
    if (!record) {
      return renderDetailEmptyState(t);
    }

    return `
      <div class="detail-sheet slide-in-right">
        <div class="detail-header">
          <div>
            <h2>${escapeHtml(record.entry.title)}</h2>
          </div>
          <div class="detail-actions">
            <button class="ghost-button" type="button" data-action="restore-entry" data-entry-id="${escapeHtml(record.entry.id)}">${escapeHtml(t("common.restore"))}</button>
            <button class="danger-button" type="button" data-action="permanent-delete" data-entry-id="${escapeHtml(record.entry.id)}">${escapeHtml(t("common.delete"))}</button>
          </div>
        </div>
        <div class="detail-grid">
          ${renderFieldCard(t("common.usernameOrEmail"), record.entry.username || "—")}
          ${renderFieldCard(t("common.url"), record.entry.url || "—")}
        </div>
      </div>
    `;
  }

  if (!derived.selectedRecord) {
    return renderDetailEmptyState(t);
  }

  const entry = derived.selectedRecord;
  const revealPassword = state.ui.revealDetailPassword;
  const category = derived.categoryById[entry.category_id] || null;
  const passwordValue = revealPassword ? entry.password || "—" : entry.password ? "••••••••" : "—";

  return `
    <div class="detail-sheet slide-in-right">
      <div class="detail-header">
        <div>
          <h2>${escapeHtml(entry.title)}</h2>
        </div>
        <div class="detail-actions">
          <button
            class="ghost-button ${state.ui.clipboardHasContent && !state.ui.clipboardCountdown ? "is-attention" : ""}"
            type="button"
            data-action="clear-clipboard"
            ${state.ui.clipboardHasContent ? "" : "disabled"}
          >
            ${escapeHtml(t("common.clearClipboard"))}
          </button>
          <button class="ghost-button" type="button" data-action="open-entry-modal" data-entry-id="${escapeHtml(entry.id)}">${escapeHtml(t("common.edit"))}</button>
          <button class="danger-button" type="button" data-action="delete-entry" data-entry-id="${escapeHtml(entry.id)}">${escapeHtml(t("common.delete"))}</button>
        </div>
      </div>

      <div class="detail-grid">
        ${renderFieldCard(t("common.usernameOrEmail"), entry.username || "—", {
          label: t("common.copy"),
          action: "copy-username",
          entryId: entry.id
        })}

        ${renderFieldCard(t("common.password"), passwordValue, {
          label: t("common.copy"),
          action: "copy-password",
          entryId: entry.id,
          trailingAction: `
            <button class="ghost-inline-button" type="button" data-action="toggle-detail-password">
              ${renderEyeIcon(revealPassword)}
              <span>${escapeHtml(t(revealPassword ? "common.hide" : "common.show"))}</span>
            </button>
          `,
          revealed: revealPassword
        })}

        <div class="field-card">
          <div class="field-card-head">
            <span>${escapeHtml(t("common.url"))}</span>
            <div class="field-card-actions">
              ${
                entry.url
                  ? `<button class="ghost-inline-button" type="button" data-action="prompt-open-url">${escapeHtml(t("common.open"))}</button>`
                  : ""
              }
            </div>
          </div>
          <div class="field-card-value">${escapeHtml(entry.url || "—")}</div>
        </div>

        <div class="field-card">
          <div class="field-card-head">
            <span>${escapeHtml(t("entry.category"))}</span>
          </div>
          <div class="field-card-value field-card-value-inline">
            ${renderCategoryDot(category?.color || "#7c6fe0")}
            <span>${escapeHtml(category?.name || "—")}</span>
          </div>
        </div>
      </div>

      ${renderStrengthBlock(state.selectedEntryStrength, t, "—")}

      <div class="detail-clipboard-badge ${state.ui.clipboardCountdown ? "" : "is-hidden"}" data-clipboard-countdown>
        ${escapeHtml(
          state.ui.clipboardCountdown
            ? t("vault.clipboardCountdown", { time: "5:00" })
            : t("vault.clipboardCountdown", { time: "0:00" })
        )}
      </div>
    </div>
  `;
}

function renderFieldCard(label, value, options = null) {
  return `
    <div class="field-card ${options?.revealed ? "is-revealed" : ""}">
      <div class="field-card-head">
        <span>${escapeHtml(label)}</span>
        <div class="field-card-actions">
          ${
            options?.action
              ? `<button class="ghost-inline-button" type="button" data-action="${escapeHtml(options.action)}" ${options.entryId ? `data-entry-id="${escapeHtml(options.entryId)}"` : ""}>${escapeHtml(options.label || "")}</button>`
              : ""
          }
          ${options?.trailingAction || ""}
        </div>
      </div>
      <div class="field-card-value">${escapeHtml(value || "—")}</div>
    </div>
  `;
}

function renderModals(state, derived, t) {
  const modals = [];

  if (state.forms.entry.open) {
    modals.push(renderEntryModal(state, derived, t));
  }
  if (state.forms.settings.open) {
    modals.push(renderSettingsModal(state, derived, t));
  }
  if (state.forms.changePassword.open) {
    modals.push(renderChangePasswordModal(state, t));
  }
  if (state.forms.masterPasswordPrompt.open) {
    modals.push(renderMasterPasswordPromptModal(state, t));
  }
  if (state.forms.confirm.open) {
    modals.push(renderConfirmModal(state, t));
  }

  return modals.join("");
}

function renderModalFrame(title, content, classes = "", isClosing = false) {
  return `
    <div class="modal-backdrop ${isClosing ? "is-closing" : ""}" data-modal-backdrop="true">
      <section class="modal-card ${classes} ${isClosing ? "is-closing" : ""}" data-modal-card="true">
        <header class="modal-header">
          <h2>${escapeHtml(title)}</h2>
          <button class="ghost-icon-button" type="button" data-action="close-modal" aria-label="${escapeHtml(title)}">×</button>
        </header>
        <div class="modal-body">
          ${content}
        </div>
      </section>
    </div>
  `;
}

function renderEntryModal(state, derived, t) {
  const form = state.forms.entry;
  const categories = derived.categories
    .map(
      (category) =>
        `<option value="${escapeHtml(category.id)}" ${form.draft.category_id === category.id ? "selected" : ""}>${escapeHtml(category.name)}</option>`
    )
    .join("");

  const inlineGenerator = state.forms.generator.open
    ? `
      <section class="inline-generator-panel">
        <div class="section-heading">
          <span>${escapeHtml(t("generator.title"))}</span>
          <button class="ghost-inline-button" type="button" data-action="toggle-entry-generator">${escapeHtml(t("common.close"))}</button>
        </div>
        ${renderGeneratorControls(state.forms.generator, t)}
      </section>
    `
    : "";

  return renderModalFrame(
    form.mode === "edit" ? t("entry.editTitle") : t("entry.createTitle"),
    `
      <form class="stack-form" data-form="entry">
        <label class="field">
          <span>${escapeHtml(t("common.title"))}</span>
          <input type="text" value="${escapeHtml(form.draft.title)}" data-model="entry.title" name="title" maxlength="256" required />
        </label>

        <label class="field">
          <span>${escapeHtml(t("common.usernameOrEmail"))}</span>
          <input type="text" value="${escapeHtml(form.draft.username)}" data-model="entry.username" name="username" maxlength="256" />
        </label>

        <label class="field">
          <span>${escapeHtml(t("common.password"))}</span>
          <div class="inline-field">
            <input
              class="${form.revealPassword ? "is-revealed" : ""}"
              type="${form.revealPassword ? "text" : "password"}"
              value="${escapeHtml(form.draft.password)}"
              data-model="entry.password"
              name="password"
              maxlength="1024"
            />
            <button class="ghost-inline-button" type="button" data-action="toggle-entry-password">
              ${renderEyeIcon(form.revealPassword)}
              <span>${escapeHtml(t(form.revealPassword ? "common.hide" : "common.show"))}</span>
            </button>
            <button class="ghost-inline-button" type="button" data-action="toggle-entry-generator">
              ${escapeHtml(t("common.generate"))}
            </button>
          </div>
        </label>

        ${renderStrengthBlock(form.strength, t, "—", "entry")}
        ${inlineGenerator}

        <label class="field">
          <span>${escapeHtml(t("common.url"))}</span>
          <input type="url" value="${escapeHtml(form.draft.url)}" data-model="entry.url" name="url" maxlength="2048" placeholder="https://example.com" />
        </label>

        <label class="field">
          <span>${escapeHtml(t("entry.category"))}</span>
          <select data-model="entry.category_id" name="category_id">
            ${categories}
          </select>
        </label>

        <footer class="modal-actions">
          <button class="ghost-button" type="button" data-action="close-modal">${escapeHtml(t("common.cancel"))}</button>
          <button class="primary-button" type="submit">${escapeHtml(t("common.save"))}</button>
        </footer>
      </form>
    `,
    "entry-modal-card",
    state.ui.modalClosing
  );
}

function renderGeneratorControls(form, t) {
  return `
    <div class="segmented-control">
      <button class="${form.mode === "password" ? "is-active" : ""}" type="button" data-action="set-generator-mode" data-generator-mode-button data-mode="password">${escapeHtml(t("generator.modePassword"))}</button>
      <button class="${form.mode === "passphrase" ? "is-active" : ""}" type="button" data-action="set-generator-mode" data-generator-mode-button data-mode="passphrase">${escapeHtml(t("generator.modePassphrase"))}</button>
    </div>

    <div class="generated-secret" data-generator-output>${escapeHtml(form.value || "—")}</div>
    ${renderStrengthBlock(form.strength, t, "—", "generator")}

    ${
      form.mode === "password"
        ? `
          <label class="field">
            <span>${escapeHtml(t("generator.length"))}</span>
            <input type="range" min="8" max="128" value="${form.length}" data-model="generator.length" />
            <strong data-generator-length-value>${form.length}</strong>
          </label>
          ${renderToggleField("generator.uppercase", t("generator.uppercase"), form.uppercase)}
          ${renderToggleField("generator.lowercase", t("generator.lowercase"), form.lowercase)}
          ${renderToggleField("generator.numbers", t("generator.numbers"), form.numbers)}
          ${renderToggleField("generator.symbols", t("generator.symbols"), form.symbols)}
          ${renderToggleField("generator.exclude_ambiguous", t("generator.excludeAmbiguous"), form.exclude_ambiguous)}
        `
        : `
          <label class="field">
            <span>${escapeHtml(t("generator.wordCount"))}</span>
            <input type="range" min="3" max="10" value="${form.word_count}" data-model="generator.word_count" />
            <strong data-generator-word-count-value>${form.word_count}</strong>
          </label>
          <label class="field">
            <span>${escapeHtml(t("generator.separator"))}</span>
            <input type="text" value="${escapeHtml(form.separator)}" data-model="generator.separator" maxlength="3" />
          </label>
        `
    }

    <footer class="modal-actions">
      <button class="ghost-button" type="button" data-action="regenerate-password">${escapeHtml(t("generator.regenerate"))}</button>
      <button class="ghost-button" type="button" data-action="copy-generated-password">${escapeHtml(t("generator.copyGenerated"))}</button>
      <button class="primary-button" type="button" data-action="use-generated-password">${escapeHtml(t("generator.useThisPassword"))}</button>
    </footer>
  `;
}

function renderToggleField(model, label, checked) {
  return `
    <label class="checkbox-row">
      <input type="checkbox" ${checked ? "checked" : ""} data-model="${model}" />
      <span>${escapeHtml(label)}</span>
    </label>
  `;
}

function renderAccordionSection(title, section, isOpen, body) {
  return `
    <section class="settings-accordion-section ${isOpen ? "is-open" : ""}" data-settings-section="${escapeHtml(section)}">
      <button
        class="settings-accordion-toggle"
        type="button"
        data-action="toggle-settings-section"
        data-section="${escapeHtml(section)}"
        aria-expanded="${isOpen ? "true" : "false"}"
      >
        <span>${escapeHtml(title)}</span>
        <span class="settings-accordion-icon">${renderChevronIcon()}</span>
      </button>
      <div class="settings-accordion-panel">
        <div class="settings-accordion-panel-inner">
          ${body}
        </div>
      </div>
    </section>
  `;
}

function renderSettingsModal(state, derived, t) {
  const form = state.forms.settings;

  const generalSection = `
    <label class="field">
      <span>${escapeHtml(t("settings.language"))}</span>
      <select data-model="settings.language">
        <option value="en" ${form.language === "en" ? "selected" : ""}>English</option>
        <option value="de" ${form.language === "de" ? "selected" : ""}>Deutsch</option>
      </select>
    </label>

    <label class="field">
      <span>${escapeHtml(t("settings.theme"))}</span>
      <div class="theme-radio-group">
        <label class="theme-radio">
          <input type="radio" name="settings-theme" value="dark" data-model="settings.theme" ${form.theme === "dark" ? "checked" : ""} />
          <span>${escapeHtml(t("common.dark"))}</span>
        </label>
        <label class="theme-radio">
          <input type="radio" name="settings-theme" value="light" data-model="settings.theme" ${form.theme === "light" ? "checked" : ""} />
          <span>${escapeHtml(t("common.light"))}</span>
        </label>
      </div>
    </label>

    <label class="field">
      <span>${escapeHtml(t("settings.autoLock"))}</span>
      <select data-model="settings.auto_lock_minutes">
        ${renderOptionMap(t, "settings.autoLockOptions", form.auto_lock_minutes)}
      </select>
    </label>

    <label class="field">
      <span>${escapeHtml(t("settings.clipboardTimeout"))}</span>
      <select data-model="settings.clipboard_timeout_secs">
        ${renderOptionMap(t, "settings.clipboardTimeoutOptions", form.clipboard_timeout_secs)}
      </select>
      <small class="field-hint">${escapeHtml(t("settings.clipboardTimeoutHint"))}</small>
    </label>

    <div class="settings-inline-actions">
      <button class="ghost-button" type="button" data-action="reset-clipboard-preference">${escapeHtml(t("settings.resetClipboardPreference"))}</button>
      <button class="ghost-button" type="button" data-action="open-change-password-modal">${escapeHtml(t("settings.changeMasterPassword"))}</button>
    </div>

    <footer class="modal-actions">
      <button class="primary-button" type="submit">${escapeHtml(t("settings.saveChanges"))}</button>
    </footer>
  `;

  const securitySection = `
    <section class="settings-subsection">
      ${renderShortcutTable(t)}
    </section>
  `;

  const dataSection = `
    ${renderImportSection(state, t)}
    ${renderExportSection(state, t)}
  `;

  const aboutSection = `
    <div class="settings-about">
      <div class="settings-about-header">
        <img src="${LOGO_SRC}" alt="" />
        <div>
          <strong>${escapeHtml(t("app.name"))}</strong>
          <span>${escapeHtml(t("settings.version"))} 0.1.0</span>
        </div>
      </div>
      <p>${escapeHtml(t("settings.aboutBlurb"))}</p>
      <button class="about-link-button" type="button" data-action="open-repo-link">↗ github.com/Viperzz6988/VaultGuard</button>
    </div>
  `;

  return renderModalFrame(
    t("settings.title"),
    `
      <form class="settings-shell" data-form="settings">
        <div class="settings-accordion">
        ${renderAccordionSection(t("settings.generalTitle"), "general", form.expanded_section === "general", generalSection)}
        ${renderAccordionSection(t("settings.securityTitle"), "shortcuts", form.expanded_section === "shortcuts", securitySection)}
        ${renderAccordionSection(t("settings.dataTitle"), "data", form.expanded_section === "data", dataSection)}
        </div>
        ${aboutSection}
      </form>
    `,
    "settings-modal-card",
    state.ui.modalClosing
  );
}

function renderImportSection(state, t) {
  return `
    <section class="settings-data-section">
      <div class="section-heading">
        <span>${escapeHtml(t("common.import"))}</span>
      </div>
      <label class="field">
        <span>${escapeHtml(t("import.type"))}</span>
        <select data-model="import.type">
          <option value="bitwarden" ${state.forms.import.type === "bitwarden" ? "selected" : ""}>${escapeHtml(t("import.types.bitwarden"))}</option>
          <option value="keepass" ${state.forms.import.type === "keepass" ? "selected" : ""}>${escapeHtml(t("import.types.keepass"))}</option>
          <option value="1password" ${state.forms.import.type === "1password" ? "selected" : ""}>${escapeHtml(t("import.types.onepassword"))}</option>
          <option value="lastpass" ${state.forms.import.type === "lastpass" ? "selected" : ""}>${escapeHtml(t("import.types.lastpass"))}</option>
          <option value="dashlane" ${state.forms.import.type === "dashlane" ? "selected" : ""}>${escapeHtml(t("import.types.dashlane"))}</option>
          <option value="generic" ${state.forms.import.type === "generic" ? "selected" : ""}>${escapeHtml(t("import.types.genericCsv"))}</option>
        </select>
      </label>

      <div class="settings-file-row">
        <button class="ghost-button settings-file-button" type="button" data-action="choose-import-file-trigger">
          ${escapeHtml(t("import.chooseFile"))}
        </button>
        <span class="subtle-text">${escapeHtml(state.forms.import.fileName || t("import.previewEmpty"))}</span>
      </div>

      <button class="primary-button data-action-button" type="button" data-action="run-import">${escapeHtml(t("import.importNow"))}</button>
    </section>
  `;
}

function renderExportSection(state, t) {
  return `
    <section class="settings-data-section">
      <div class="section-heading">
        <span>${escapeHtml(t("common.export"))}</span>
      </div>
      <article class="export-card data-export-card">
        <h3>${escapeHtml(t("settings.exportBackup"))}</h3>
        <p>${escapeHtml(t("export.backupDescription"))}</p>
        <button class="primary-button data-action-button" type="button" data-action="run-export" data-export-type="encrypted">${escapeHtml(t("settings.exportBackup"))}</button>
      </article>

      <article class="export-card data-export-card">
        <h3>${escapeHtml(t("settings.exportKeepassXml"))}</h3>
        <p>${escapeHtml(t("export.keepassDescription"))}</p>
        <button class="ghost-button data-action-button" type="button" data-action="run-export" data-export-type="keepass">${escapeHtml(t("settings.exportKeepassXml"))}</button>
      </article>

      <article class="export-card data-export-card">
        <h3>${escapeHtml(t("settings.exportBitwardenJson"))}</h3>
        <p>${escapeHtml(t("export.bitwardenDescription"))}</p>
        <button class="ghost-button data-action-button" type="button" data-action="run-export" data-export-type="bitwarden">${escapeHtml(t("settings.exportBitwardenJson"))}</button>
      </article>
    </section>
  `;
}

function renderConfirmModal(state, t) {
  return renderModalFrame(
    state.forms.confirm.title,
    `
      <section class="stack-form">
        <p>${escapeHtml(state.forms.confirm.message)}</p>
        <footer class="modal-actions">
          <button class="ghost-button" type="button" data-action="close-modal">${escapeHtml(t("common.cancel"))}</button>
          <button class="${state.forms.confirm.kind === "open-url" ? "primary-button" : "danger-button"}" type="button" data-action="confirm-action">${escapeHtml(state.forms.confirm.confirmLabel || t("common.confirm"))}</button>
        </footer>
      </section>
    `,
    "confirm-modal-card",
    state.ui.modalClosing
  );
}

function renderChangePasswordModal(state, t) {
  const form = state.forms.changePassword;
  return renderModalFrame(
    t("settings.changeMasterPassword"),
    `
      <form class="stack-form" data-form="change-password">
        <label class="field">
          <span>${escapeHtml(t("settings.currentPassword"))}</span>
          <input type="password" autocomplete="current-password" value="${escapeHtml(form.currentPassword)}" data-model="changePassword.currentPassword" required />
        </label>
        <label class="field">
          <span>${escapeHtml(t("settings.newPassword"))}</span>
          <input type="password" autocomplete="new-password" value="${escapeHtml(form.newPassword)}" data-model="changePassword.newPassword" required />
        </label>
        <label class="field">
          <span>${escapeHtml(t("settings.confirmNewPassword"))}</span>
          <input type="password" autocomplete="new-password" value="${escapeHtml(form.confirmNewPassword)}" data-model="changePassword.confirmNewPassword" required />
        </label>
        ${renderStrengthBlock(form.strength, t, "—", "changePassword")}
        <footer class="modal-actions">
          <button class="ghost-button" type="button" data-action="close-modal">${escapeHtml(t("common.cancel"))}</button>
          <button class="primary-button" type="submit">${escapeHtml(t("common.save"))}</button>
        </footer>
      </form>
    `,
    "change-password-card",
    state.ui.modalClosing
  );
}

function renderMasterPasswordPromptModal(state, t) {
  return renderModalFrame(
    t("settings.reenterPassword"),
    `
      <form class="stack-form" data-form="master-password-prompt">
        <p>${escapeHtml(t("export.reauthDescription"))}</p>
        <label class="field">
          <span>${escapeHtml(t("common.password"))}</span>
          <input
            type="password"
            autocomplete="current-password"
            value="${escapeHtml(state.forms.masterPasswordPrompt.password)}"
            data-model="masterPasswordPrompt.password"
            required
          />
        </label>
        <footer class="modal-actions">
          <button class="ghost-button" type="button" data-action="close-modal">${escapeHtml(t("common.cancel"))}</button>
          <button class="primary-button" type="submit">${escapeHtml(t("common.confirm"))}</button>
        </footer>
      </form>
    `,
    "change-password-card",
    state.ui.modalClosing
  );
}

function renderShortcutTable(t) {
  return `
    <div class="shortcut-grid">
      <div class="shortcut-key">Ctrl + N</div><div class="shortcut-description">${escapeHtml(t("vault.newEntry"))}</div>
      <div class="shortcut-key">Ctrl + L</div><div class="shortcut-description">${escapeHtml(t("common.lockVault"))}</div>
      <div class="shortcut-key">Ctrl + F</div><div class="shortcut-description">${escapeHtml(t("common.search"))}</div>
      <div class="shortcut-key">Ctrl + G</div><div class="shortcut-description">${escapeHtml(t("generator.title"))}</div>
      <div class="shortcut-key">Escape</div><div class="shortcut-description">${escapeHtml(t("common.close"))}</div>
      <div class="shortcut-key">?</div><div class="shortcut-description">${escapeHtml(t("settings.keyboardShortcuts"))}</div>
    </div>
  `;
}

function renderOptionMap(t, baseKey, currentValue) {
  return Object.entries(t(baseKey))
    .map(
      ([value, label]) =>
        `<option value="${escapeHtml(value)}" ${String(currentValue) === value ? "selected" : ""}>${escapeHtml(label)}</option>`
    )
    .join("");
}

export function renderToasts(state) {
  if (!state.toasts.length) {
    return `<div class="toast-stack" aria-live="polite"></div>`;
  }

  return `
    <div class="toast-stack" aria-live="polite">
      ${state.toasts
        .map(
          (toast) => `
            <article class="toast ${toast.tone || "info"}">
              <strong>${escapeHtml(toast.message)}</strong>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderClipboardChoicePopup(state, t) {
  const choice = state.ui.clipboardChoice;
  const hidden = !choice;
  const left = Number(choice?.left || 0);
  const top = Number(choice?.top || 0);
  const timeoutOptions = t("settings.clipboardTimeoutOptions");
  const timeoutLabel = timeoutOptions[String(choice?.timeoutSecs || 300)] || timeoutOptions["300"];

  return `
    <div
      class="clipboard-choice-popup ${hidden ? "is-hidden" : ""}"
      style="left:${left}px;top:${top}px;"
      data-clipboard-choice-popup
    >
      <div class="clipboard-choice-title">✓ ${escapeHtml(t("vault.clipboardChoiceCopied"))}</div>
      <p class="clipboard-choice-copy-label">${escapeHtml(choice?.label || t("common.copy"))}</p>
      <div class="clipboard-choice-subtitle">${escapeHtml(t("vault.clipboardChoicePrompt"))}</div>
      <div class="clipboard-choice-options">
        <label class="theme-radio clipboard-choice-option">
          <input type="radio" name="clipboard-choice-mode" value="manual" data-model="clipboardChoice.mode" ${choice?.mode === "manual" ? "checked" : ""} />
          <span>${escapeHtml(t("vault.clipboardChoiceKeepForever"))}</span>
        </label>
        <label class="theme-radio clipboard-choice-option">
          <input type="radio" name="clipboard-choice-mode" value="timed" data-model="clipboardChoice.mode" ${choice?.mode !== "manual" ? "checked" : ""} />
          <span>${escapeHtml(timeoutLabel)}</span>
        </label>
      </div>
      <label class="checkbox-row clipboard-choice-remember">
        <input type="checkbox" data-model="clipboardChoice.remember" ${choice?.remember ? "checked" : ""} />
        <span>${escapeHtml(t("vault.clipboardChoiceRemember"))}</span>
      </label>
      <div class="clipboard-choice-actions">
        <button class="ghost-button" type="button" data-action="clipboard-choice-cancel">
          ${escapeHtml(t("common.cancel"))}
        </button>
        <button class="primary-button" type="button" data-action="clipboard-choice-confirm">
          ${escapeHtml(t("common.confirm"))}
        </button>
      </div>
      <div class="clipboard-choice-dismiss" data-clipboard-choice-dismiss>
        ${escapeHtml(t("vault.clipboardChoiceDismiss", { seconds: choice?.remaining || 0 }))}
      </div>
    </div>
  `;
}

export function renderApp({ state, derived, t }) {
  if (!state.ready) {
    return renderLoadingShell();
  }

  if (state.ui.postLoginLoading) {
    return `${renderPostLoginLoading(t)}${renderClipboardChoicePopup(state, t)}${renderToasts(state)}`;
  }

  if (state.ui.startupIntegrityAlert) {
    return `${renderIntegrityAlertScreen(state, t)}${renderClipboardChoicePopup(state, t)}${renderToasts(state)}`;
  }

  const content = !state.vaultExists
    ? renderSetupScreen(state, t)
    : state.forms.setupConfirmation.stage === "warning"
      ? renderSetupWarningScreen(t)
    : state.forms.setupConfirmation.stage === "confirm"
      ? renderSetupReadyScreen(state, t)
      : state.forms.setupConfirmation.stage === "integrity"
        ? renderSetupIntegrityScreen(t)
        : !state.unlocked
          ? renderUnlockScreen(state, t)
          : renderVaultScreen(state, derived, t);

  if (!state.unlocked && state.ui.startupIntro?.active) {
    return `${renderStartupIntro(content)}${renderClipboardChoicePopup(state, t)}${renderToasts(state)}`;
  }

  return `${content}${renderClipboardChoicePopup(state, t)}${renderToasts(state)}`;
}
