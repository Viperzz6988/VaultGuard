const DEFAULT_LANGUAGE = "en";
const dictionaries = new Map();
let currentLanguage = DEFAULT_LANGUAGE;

async function loadDictionary(language) {
  if (dictionaries.has(language)) {
    return dictionaries.get(language);
  }

  const response = await fetch(`/locales/${language}.json`);
  if (!response.ok) {
    throw new Error(`Failed to load locale ${language}`);
  }

  const dictionary = await response.json();
  dictionaries.set(language, dictionary);
  return dictionary;
}

function getNestedValue(dictionary, key) {
  return key.split(".").reduce((value, part) => value?.[part], dictionary);
}

export async function initI18n(language = DEFAULT_LANGUAGE) {
  const targetLanguage = language || DEFAULT_LANGUAGE;
  await Promise.all([loadDictionary(DEFAULT_LANGUAGE), loadDictionary(targetLanguage)]);
  currentLanguage = targetLanguage;
}

export async function setLanguage(language) {
  await initI18n(language);
}

export function getLanguage() {
  return currentLanguage;
}

export function t(key, variables = {}) {
  const currentDictionary = dictionaries.get(currentLanguage) || {};
  const fallbackDictionary = dictionaries.get(DEFAULT_LANGUAGE) || {};
  const template =
    getNestedValue(currentDictionary, key) ??
    getNestedValue(fallbackDictionary, key) ??
    key;

  if (typeof template !== "string") {
    return template;
  }

  return template.replace(/\{(\w+)\}/g, (_, token) => {
    const value = variables[token];
    return value === undefined || value === null ? "" : String(value);
  });
}

export function optionLabel(key, optionKey) {
  return t(`${key}.${optionKey}`);
}

export function formatDateTime(value) {
  if (!value) {
    return "—";
  }

  try {
    return new Intl.DateTimeFormat(currentLanguage, {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(new Date(value));
  } catch {
    return value;
  }
}
