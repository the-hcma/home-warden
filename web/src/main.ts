// Entry point for home-warden's admin web UI (#55 / #68).
//
// Intentionally minimal: just enough DOM + fetch plumbing to prove the
// PAM-backed login, session cookie, and logout flow end-to-end. Real admin
// panels land in later sub-issues (#69 catalog CRUD, #70 health dashboard).

type SessionResponse = {
  authenticated: true;
  username: string;
};

const appPath = "/";
const loginPath = "/login";

function mountAppShell(root: HTMLElement): void {
  renderAppShell(root).catch((error: unknown) => {
    // readSession()/logout() throw on a 500/503 or a dropped connection --
    // without this catch the rejection was silently swallowed, leaving the
    // operator staring at an empty #app with no message and no redirect.
    console.error("home-warden: failed to render app shell", error);
    const message = error instanceof Error ? error.message : "Failed to load session";
    const errorNode = document.createElement("p");
    errorNode.textContent = message;
    root.replaceChildren(errorNode);
  });
}

function mountLoginForm(root: HTMLElement): void {
  let errorNode: HTMLParagraphElement | null = null;

  const heading = document.createElement("h1");
  heading.textContent = "home-warden login";

  const form = document.createElement("form");
  const passwordInput = document.createElement("input");
  const passwordLabel = document.createElement("label");
  const submitButton = document.createElement("button");
  const usernameInput = document.createElement("input");
  const usernameLabel = document.createElement("label");

  form.autocomplete = "on";
  passwordInput.autocomplete = "current-password";
  passwordInput.name = "password";
  passwordInput.required = true;
  passwordInput.type = "password";
  passwordLabel.textContent = "Password";
  passwordLabel.htmlFor = "password";
  passwordInput.id = passwordLabel.htmlFor;
  submitButton.textContent = "Log in";
  submitButton.type = "submit";
  usernameInput.autocomplete = "username";
  usernameInput.id = "username";
  usernameInput.name = "username";
  usernameInput.required = true;
  usernameLabel.textContent = "Username";
  usernameLabel.htmlFor = usernameInput.id;

  form.append(
    usernameLabel,
    document.createElement("br"),
    usernameInput,
    document.createElement("br"),
    passwordLabel,
    document.createElement("br"),
    passwordInput,
    document.createElement("br"),
    submitButton,
  );

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    submitButton.disabled = true;
    clearLoginError();
    void login(usernameInput.value, passwordInput.value)
      .then(() => {
        window.location.assign(appPath);
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : "Login failed";
        errorNode = document.createElement("p");
        errorNode.textContent = message;
        root.append(errorNode);
      })
      .finally(() => {
        submitButton.disabled = false;
      });
  });

  root.append(heading, form);

  function clearLoginError(): void {
    if (errorNode) {
      errorNode.remove();
      errorNode = null;
    }
  }
}

function mountPage(root: HTMLElement): void {
  if (window.location.pathname === loginPath) {
    mountLoginForm(root);
    return;
  }
  mountAppShell(root);
}

async function login(username: string, password: string): Promise<void> {
  const response = await fetch("/auth/login", {
    body: JSON.stringify({ password, username }),
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
}

async function logout(): Promise<void> {
  const response = await fetch("/auth/logout", {
    credentials: "same-origin",
    method: "POST",
  });
  if (!response.ok) {
    // Don't navigate to /login on a failed logout -- the session cookie is
    // still valid server-side, so /login would just 303 straight back to
    // "/" with no indication anything went wrong.
    throw new Error(await errorMessage(response));
  }
  window.location.assign(loginPath);
}

async function renderAppShell(root: HTMLElement): Promise<void> {
  const session = await readSession();
  if (!session) {
    window.location.assign(loginPath);
    return;
  }

  const heading = document.createElement("h1");
  const logoutButton = document.createElement("button");
  const summary = document.createElement("p");
  let logoutErrorNode: HTMLParagraphElement | null = null;

  heading.textContent = "home-warden";
  logoutButton.textContent = "Log out";
  logoutButton.type = "button";
  summary.textContent = `Signed in as ${session.username}.`;
  logoutButton.addEventListener("click", () => {
    logoutButton.disabled = true;
    logout()
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : "Log out failed";
        logoutErrorNode?.remove();
        logoutErrorNode = document.createElement("p");
        logoutErrorNode.textContent = message;
        root.append(logoutErrorNode);
      })
      .finally(() => {
        logoutButton.disabled = false;
      });
  });

  root.replaceChildren(heading, summary, logoutButton);
}

async function readSession(): Promise<SessionResponse | null> {
  const response = await fetch("/auth/session", {
    credentials: "same-origin",
    method: "GET",
  });
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
  return (await response.json()) as SessionResponse;
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string" && body.detail) {
      return body.detail;
    }
  } catch {
    // Ignore non-JSON error bodies and fall back to the status text.
  }
  return response.statusText || "Request failed";
}

const root = document.getElementById("app");
if (root) {
  mountPage(root);
} else {
  console.error("home-warden: #app root element not found");
}
