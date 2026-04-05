export function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function tokenize(query) {
  return query
    .toLowerCase()
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean);
}

function subsequenceScore(text, token) {
  let tokenIndex = 0;
  let streak = 0;

  for (const char of text) {
    if (char === token[tokenIndex]) {
      tokenIndex += 1;
      streak += 1;
      if (tokenIndex === token.length) {
        return streak;
      }
    }
  }

  return 0;
}

function fieldScore(fieldValue, tokens, weight) {
  const value = String(fieldValue || "").toLowerCase();
  if (!value) {
    return { score: 0, matched: false };
  }

  let score = 0;
  let matched = false;

  for (const token of tokens) {
    if (value.includes(token)) {
      score += weight * 10;
      matched = true;
      continue;
    }

    const subsequence = subsequenceScore(value, token);
    if (subsequence > 0) {
      score += weight * subsequence;
      matched = true;
    }
  }

  return { score, matched };
}

export function filterEntries(entries, query, filters = {}) {
  const tokens = tokenize(query);
  const selectedCategory = filters.categoryId || "all";

  const inScopeEntries = entries.filter((entry) => {
    if (selectedCategory !== "all" && entry.category_id !== selectedCategory) {
      return false;
    }

    return true;
  });

  if (tokens.length === 0) {
    return inScopeEntries
      .map((entry) => ({ entry, score: 0 }))
      .sort((left, right) => {
        return (
          String(left.entry.category_id || "").localeCompare(String(right.entry.category_id || "")) ||
          Number(left.entry.sort_order || 0) - Number(right.entry.sort_order || 0) ||
          new Date(right.entry.modified_at).getTime() - new Date(left.entry.modified_at).getTime()
        );
      });
  }

  const filtered = inScopeEntries
    .map((entry) => {
      const title = fieldScore(entry.title, tokens, 5);
      const username = fieldScore(entry.username, tokens, 4);
      const url = fieldScore(entry.url, tokens, 3);

      const score = title.score + username.score + url.score;
      const matched = [title, username, url].some((field) => field.matched);
      return matched ? { entry, score } : null;
    })
    .filter(Boolean);

  return filtered.sort((left, right) => {
    return (
      right.score - left.score ||
      new Date(right.entry.modified_at).getTime() - new Date(left.entry.modified_at).getTime()
    );
  });
}

export function collectTags(entries) {
  const unique = new Set();
  for (const entry of entries) {
    for (const tag of entry.tags || []) {
      if (tag) {
        unique.add(tag);
      }
    }
  }
  return Array.from(unique).sort((left, right) => left.localeCompare(right));
}

export function highlightText(value, query) {
  const safeValue = escapeHtml(value || "");
  const tokens = tokenize(query);
  if (!safeValue || tokens.length === 0) {
    return safeValue;
  }

  const pattern = tokens.map(escapeForRegex).join("|");
  const regex = new RegExp(`(${pattern})`, "gi");
  return safeValue.replace(regex, "<mark>$1</mark>");
}

export function summarizeNotes(notes = "", query = "") {
  if (!notes) {
    return "";
  }

  const trimmed = notes.trim();
  if (trimmed.length <= 120) {
    return highlightText(trimmed, query);
  }

  return `${highlightText(trimmed.slice(0, 117), query)}…`;
}

function escapeForRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
