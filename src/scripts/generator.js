export const DEFAULT_GENERATOR_STATE = {
  mode: "password",
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  exclude_ambiguous: true,
  word_count: 4,
  separator: "-"
};

export function normalizeGeneratorState(partial = {}) {
  const next = { ...DEFAULT_GENERATOR_STATE, ...partial };

  next.length = clampNumber(next.length, 8, 128, DEFAULT_GENERATOR_STATE.length);
  next.word_count = clampNumber(next.word_count, 3, 10, DEFAULT_GENERATOR_STATE.word_count);
  next.separator = typeof next.separator === "string" ? next.separator : DEFAULT_GENERATOR_STATE.separator;

  if (!next.uppercase && !next.lowercase && !next.numbers && !next.symbols) {
    next.lowercase = true;
  }

  return next;
}

export function emptyEntryDraft(categoryId = "builtin-login") {
  return {
    id: null,
    title: "",
    username: "",
    password: "",
    url: "",
    category_id: categoryId,
    notes: null,
    tags: [],
    custom_fields: [],
    favorite: false
  };
}

export function draftFromEntry(entry) {
  return {
    id: entry.id,
    title: entry.title || "",
    username: entry.username || "",
    password: entry.password || "",
    url: entry.url || "",
    category_id: entry.category_id || "builtin-login",
    notes: entry.notes || null,
    tags: [...(entry.tags || [])],
    custom_fields: (entry.custom_fields || []).map((field) => ({
      key: field.key || "",
      value: field.value || "",
      hidden: Boolean(field.hidden)
    })),
    favorite: Boolean(entry.favorite)
  };
}

export function emptyCustomField() {
  return {
    key: "",
    value: "",
    hidden: false
  };
}

export function buildEntryPayload(formData, draft) {
  return {
    title: (formData.get("title") || "").trim(),
    username: emptyToNull(formData.get("username")),
    password: emptyToNull(formData.get("password")),
    url: emptyToNull(formData.get("url")),
    notes: draft.notes || null,
    category_id: emptyToNull(formData.get("category_id")) || "builtin-login",
    tags: [...(draft.tags || [])],
    favorite: Boolean(draft.favorite),
    custom_fields: (draft.custom_fields || [])
      .map((field) => ({
        key: (field.key || "").trim(),
        value: field.value || "",
        hidden: Boolean(field.hidden)
      }))
      .filter((field) => field.key.length > 0)
  };
}

export function parseTags(value) {
  return String(value || "")
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
}

function emptyToNull(value) {
  const normalized = String(value || "").trim();
  return normalized ? normalized : null;
}

function clampNumber(value, min, max, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(Math.max(Math.round(numeric), min), max);
}
