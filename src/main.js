const STARTUP_ERROR_TITLE = "Failed to start VaultGuard";

function renderStartupError(error) {
  const title = document.createElement("h2");
  title.textContent = STARTUP_ERROR_TITLE;

  const description = document.createElement("p");
  description.textContent = "VaultGuard could not finish loading.";

  const details = document.createElement("pre");
  details.textContent = error instanceof Error ? error.message : String(error);

  const container = document.createElement("div");
  container.className = "startup-error";
  container.append(title, description, details);

  document.body.replaceChildren(container);
}

async function startApplication() {
  try {
    const { initializeApp } = await import("/scripts/app.js");
    await initializeApp();
  } catch (error) {
    console.error("VaultGuard startup failed", error);
    renderStartupError(error);
  }
}

function bootstrapApplication() {
  document.addEventListener("contextmenu", (event) => event.preventDefault());
  void startApplication();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootstrapApplication, { once: true });
} else {
  bootstrapApplication();
}
