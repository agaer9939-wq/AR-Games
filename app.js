const authModal = document.querySelector("#auth-modal");
const authForm = document.querySelector("#auth-form");
const verificationForm = document.querySelector("#verification-form");
const authTabs = document.querySelector(".auth-tabs");
const toast = document.querySelector("#toast");
let currentUser = null;
let authMode = "login";
let pendingVerificationEmail = "";
let toastTimer;

async function request(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}

function notify(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2600);
}

function setUser(user) {
  currentUser = user;
  const accountButton = document.querySelector("#account-button");
  accountButton.textContent = user ? `Hi, ${user.username}` : "Sign in ↗";
}

function openAuth(mode = "login") {
  authModal.hidden = false;
  document.body.style.overflow = "hidden";
  setAuthMode(mode);
  authModal.querySelector("input:not([type='hidden'])")?.focus();
}

function closeModal() {
  authModal.hidden = true;
  document.body.style.overflow = "";
}

function showVerification(email) {
  pendingVerificationEmail = email;
  document.querySelector("#verification-email").textContent = email;
  authForm.hidden = true;
  authTabs.hidden = true;
  verificationForm.hidden = false;
  document.querySelector("#auth-title").textContent = "Check your inbox.";
  document.querySelector("#auth-description").textContent = "One last step to create your account.";
  document.querySelector("#verification-error").hidden = true;
  verificationForm.elements.code.focus();
}

function setAuthMode(mode) {
  authMode = mode;
  const isRegister = mode === "register";
  authForm.hidden = false;
  authTabs.hidden = false;
  verificationForm.hidden = true;
  document.querySelector("#auth-title").textContent = isRegister ? "Join us." : "Welcome back.";
  document.querySelector("#auth-description").textContent = isRegister
    ? "Create your account and get ready for what's next."
    : "Sign in to your account.";
  document.querySelector("#username-field").hidden = !isRegister;
  authForm.elements.username.required = isRegister;
  authForm.elements.password.autocomplete = isRegister ? "new-password" : "current-password";
  document.querySelector("#submit-label").textContent = isRegister ? "Create my account" : "Sign in";
  document.querySelectorAll(".auth-tab").forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  document.querySelector("#form-error").hidden = true;
}

async function loadApp() {
  try {
    const { user } = await request("/api/me");
    setUser(user);
  } catch (error) {
    notify(error.message);
  }
}

document.querySelector("#account-button").addEventListener("click", async () => {
  if (!currentUser) {
    openAuth("login");
    return;
  }
  if (confirm(`Sign out of ${currentUser.username}'s account?`)) {
    try {
      await request("/api/logout", { method: "POST", body: "{}" });
      setUser(null);
      notify("You have been signed out.");
    } catch (error) {
      notify(error.message);
    }
  }
});

["#hero-account", "#community-account"].forEach((selector) => {
  document.querySelector(selector).addEventListener("click", () => openAuth(currentUser ? "login" : "register"));
});

document.querySelectorAll(".auth-tab").forEach((tab) => tab.addEventListener("click", () => setAuthMode(tab.dataset.mode)));
document.querySelector(".modal-close").addEventListener("click", closeModal);
authModal.addEventListener("click", (event) => {
  if (event.target === authModal) closeModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeModal();
});

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = authForm.querySelector("button[type='submit']");
  const errorBox = document.querySelector("#form-error");
  const payload = Object.fromEntries(new FormData(authForm));
  submitButton.disabled = true;
  errorBox.hidden = true;
  try {
    const result = await request(authMode === "register" ? "/api/register" : "/api/login", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    if (result.verificationRequired) {
      showVerification(result.email);
      notify(result.message);
      return;
    }
    setUser(result.user);
    closeModal();
    authForm.reset();
    notify(authMode === "register" ? `Welcome, ${result.user.username}. Your account is ready.` : `Welcome back, ${result.user.username}.`);
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  } finally {
    submitButton.disabled = false;
  }
});

verificationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = verificationForm.querySelector("button[type='submit']");
  const errorBox = document.querySelector("#verification-error");
  submitButton.disabled = true;
  errorBox.hidden = true;
  try {
    const result = await request("/api/verify-email", {
      method: "POST",
      body: JSON.stringify({
        email: pendingVerificationEmail,
        code: verificationForm.elements.code.value
      })
    });
    setUser(result.user);
    closeModal();
    authForm.reset();
    verificationForm.reset();
    pendingVerificationEmail = "";
    notify(`Email verified. Welcome, ${result.user.username}.`);
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  } finally {
    submitButton.disabled = false;
  }
});

document.querySelector("#resend-code").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await request("/api/resend-verification", {
      method: "POST",
      body: JSON.stringify({ email: pendingVerificationEmail })
    });
    notify(result.message);
  } catch (error) {
    notify(error.message);
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#menu-toggle").addEventListener("click", (event) => {
  const nav = document.querySelector(".main-nav");
  const expanded = nav.classList.toggle("open");
  event.currentTarget.setAttribute("aria-expanded", String(expanded));
});
document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.toggle("active", item === link));
    document.querySelector(".main-nav").classList.remove("open");
    document.querySelector("#menu-toggle").setAttribute("aria-expanded", "false");
  });
});

loadApp();
