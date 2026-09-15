// Entry point for home-warden's admin web UI (#55 / #68 / #69).
//
// Still intentionally framework-free: plain DOM + fetch keeps the first UI
// issues small and inspectable while the backend contract settles.

type CatalogAction = "create" | "delete" | "update";
type ServiceKind = "proxy" | "static";
type SessionResponse = {
  authenticated: true;
  username: string;
};

type JsonPrimitive = boolean | null | number | string;
type JsonValue = JsonObject | JsonPrimitive | JsonValue[];
type JsonObject = { [key: string]: JsonValue };
type ManagedBy = JsonObject;
type StaticConfig = JsonObject & {
  listing_path?: null | string;
  root: string;
};
type UpstreamConfig = JsonObject & {
  host: string;
  path?: string;
  port: number;
  scheme?: "http" | "https";
};
type ServiceEntry = JsonObject & {
  allow_cidrs?: null | string[];
  client_cert?: JsonObject;
  forward_host_header?: boolean | null;
  gzip?: boolean | null;
  kind: ServiceKind;
  managed_by?: ManagedBy;
  name: string;
  server_name: string;
  static?: null | StaticConfig;
  upstream?: null | UpstreamConfig;
  websocket?: boolean | null;
};
type CatalogMutationRequest = {
  action: CatalogAction;
  name?: string;
  service?: ServiceEntry;
};
type PreviewResponse = {
  can_apply: boolean;
  diff: string;
  gixy: {
    exit_code: number | null;
    output: string;
    status: "error" | "findings" | "ok";
  };
  nginx_test: {
    exit_code: number | null;
    ok: boolean;
    output: string;
    status: "failed" | "ok" | "unavailable";
  };
  rendered: string;
};
type ApplyResponse = {
  deleted_name?: string;
  preview: PreviewResponse;
  service?: ServiceEntry;
};
type FormState = {
  allowCidrs: string;
  forwardHostHeader: boolean;
  gzipDisabled: boolean;
  kind: ServiceKind;
  name: string;
  serverName: string;
  staticListingPath: string;
  staticRoot: string;
  upstreamHost: string;
  upstreamPath: string;
  upstreamPort: string;
  upstreamScheme: "http" | "https";
  websocket: boolean;
};
type CatalogState = {
  applying: boolean;
  error: string | null;
  form: FormState;
  loading: boolean;
  message: string | null;
  originalService: ServiceEntry | null;
  preview: PreviewResponse | null;
  previewRequest: CatalogMutationRequest | null;
  services: ServiceEntry[];
};

const appPath = "/";
const loginPath = "/login";

function blankFormState(): FormState {
  return {
    allowCidrs: "",
    forwardHostHeader: false,
    gzipDisabled: false,
    kind: "proxy",
    name: "",
    serverName: "",
    staticListingPath: "",
    staticRoot: "",
    upstreamHost: "",
    upstreamPath: "/",
    upstreamPort: "8080",
    upstreamScheme: "http",
    websocket: false,
  };
}

function buildServiceFromForm(form: FormState, base: ServiceEntry | null, forUpdate: boolean): ServiceEntry {
  const service = base ? cloneJson(base) : ({} as ServiceEntry);

  service.kind = form.kind;
  service.name = form.name.trim();
  service.server_name = form.serverName.trim();

  if (form.kind === "proxy") {
    if (forUpdate) {
      service.static = null;
    } else {
      delete service.static;
    }
    service.upstream = {
      ...(service.upstream ?? {}),
      host: form.upstreamHost.trim(),
      path: form.upstreamPath.trim() || "/",
      port: Number(form.upstreamPort),
      scheme: form.upstreamScheme,
    };
  } else {
    if (forUpdate) {
      service.upstream = null;
    } else {
      delete service.upstream;
    }
    const staticConfig: StaticConfig = {
      ...(service.static ?? {}),
      root: form.staticRoot.trim(),
    };
    service.static = staticConfig;
    if (form.staticListingPath.trim()) {
      staticConfig.listing_path = form.staticListingPath.trim();
    } else if (forUpdate) {
      staticConfig.listing_path = null;
    } else {
      delete staticConfig.listing_path;
    }
  }

  if (form.allowCidrs.trim()) {
    service.allow_cidrs = parseAllowCidrs(form.allowCidrs);
  } else if (forUpdate) {
    service.allow_cidrs = null;
  } else {
    delete service.allow_cidrs;
  }

  if (form.forwardHostHeader) {
    service.forward_host_header = true;
  } else if (forUpdate) {
    service.forward_host_header = null;
  } else {
    delete service.forward_host_header;
  }

  if (form.gzipDisabled) {
    service.gzip = false;
  } else if (forUpdate) {
    service.gzip = null;
  } else {
    delete service.gzip;
  }

  if (form.websocket) {
    service.websocket = true;
  } else if (forUpdate) {
    service.websocket = null;
  } else {
    delete service.websocket;
  }

  return service;
}

function cloneJson<T extends JsonValue>(value: T): T {
  return structuredClone(value);
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

async function fetchJson<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
  return (await response.json()) as T;
}

async function login(username: string, password: string): Promise<void> {
  await fetchJson<{ authenticated: true; username: string }>("/auth/login", {
    body: JSON.stringify({ password, username }),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
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

function mountCatalogManager(root: HTMLElement): void {
  const state: CatalogState = {
    applying: false,
    error: null,
    form: blankFormState(),
    loading: true,
    message: null,
    originalService: null,
    preview: null,
    previewRequest: null,
    services: [],
  };

  void refreshServices().finally(render);

  function invalidatePreview(): void {
    state.preview = null;
    state.previewRequest = null;
  }

  function markPreviewStale(): void {
    const hadPreview = state.preview !== null || state.previewRequest !== null;
    invalidatePreview();
    if (hadPreview) {
      state.message = "Form changed — preview again before applying.";
      render();
    }
  }

  function resetEditor(): void {
    state.form = blankFormState();
    state.originalService = null;
    invalidatePreview();
  }

  async function applyCurrentPreview(): Promise<void> {
    if (state.applying || !state.previewRequest) {
      return;
    }

    state.applying = true;
    state.error = null;
    state.message = "Applying catalog change…";
    render();
    try {
      const result = await applyCatalogMutation(state.previewRequest);
      if (result.deleted_name) {
        resetEditor();
        state.message = `Deleted ${result.deleted_name}.`;
      } else if (result.service) {
        invalidatePreview();
        state.originalService = result.service;
        state.form = serviceToFormState(result.service);
        state.message = `Applied ${result.service.name}.`;
      } else {
        invalidatePreview();
        state.message = "Applied catalog change.";
      }
      await refreshServices();
    } catch (error: unknown) {
      state.error = error instanceof Error ? error.message : "Apply failed";
    } finally {
      state.applying = false;
    }
    render();
  }

  async function beginCreate(): Promise<void> {
    state.error = null;
    state.message = "Creating a new service.";
    resetEditor();
    render();
  }

  async function beginDelete(name: string): Promise<void> {
    state.error = null;
    state.message = `Previewing deletion of ${name}…`;
    invalidatePreview();
    render();

    try {
      const request: CatalogMutationRequest = { action: "delete", name };
      state.preview = await previewCatalogMutation(request);
      state.previewRequest = request;
      state.message = `Preview ready for deleting ${name}.`;
    } catch (error: unknown) {
      state.error = error instanceof Error ? error.message : "Preview failed";
    }
    render();
  }

  async function beginEdit(name: string): Promise<void> {
    state.error = null;
    state.message = `Loading ${name}…`;
    invalidatePreview();
    render();

    try {
      const service = await readCatalogService(name);
      state.form = serviceToFormState(service);
      state.originalService = service;
      state.message = `Editing ${name}.`;
    } catch (error: unknown) {
      state.error = error instanceof Error ? error.message : "Failed to load service";
    }
    render();
  }

  async function previewCurrentForm(): Promise<void> {
    state.error = null;
    state.message = "Rendering preview…";
    invalidatePreview();
    render();

    try {
      const nextService = buildServiceFromForm(state.form, state.originalService, state.originalService !== null);
      const request: CatalogMutationRequest = state.originalService
        ? { action: "update", name: state.originalService.name, service: nextService }
        : { action: "create", service: nextService };
      state.preview = await previewCatalogMutation(request);
      state.previewRequest = request;
      state.message = `Preview ready for ${nextService.name || "this service"}.`;
    } catch (error: unknown) {
      state.error = error instanceof Error ? error.message : "Preview failed";
    }
    render();
  }

  async function refreshServices(): Promise<void> {
    state.loading = true;
    state.error = null;
    try {
      state.services = await readCatalogServices();
    } catch (error: unknown) {
      state.error = error instanceof Error ? error.message : "Failed to load services";
      state.services = [];
    }
    state.loading = false;
  }

  function render(): void {
    const container = document.createElement("div");
    const actions = document.createElement("div");
    const heading = document.createElement("h2");
    const layout = document.createElement("div");
    const listSection = document.createElement("section");
    const editorSection = document.createElement("section");
    const previewSection = document.createElement("section");

    heading.textContent = "Service catalog";
    actions.append(heading);

    const addButton = document.createElement("button");
    addButton.textContent = "Add service";
    addButton.type = "button";
    addButton.addEventListener("click", () => {
      void beginCreate();
    });
    actions.append(addButton);

    if (state.message) {
      const messageNode = document.createElement("p");
      messageNode.textContent = state.message;
      actions.append(messageNode);
    }
    if (state.error) {
      const errorNode = document.createElement("p");
      errorNode.textContent = state.error;
      actions.append(errorNode);
    }

    listSection.append(renderServiceList());
    editorSection.append(renderServiceEditor());
    previewSection.append(renderPreviewPane());

    layout.style.display = "grid";
    layout.style.gap = "1.5rem";
    layout.append(listSection, editorSection, previewSection);

    container.append(actions, layout);
    root.replaceChildren(container);
  }

  function renderPreviewBlock(title: string, content: string, status: string): HTMLElement {
    const wrapper = document.createElement("div");
    const heading = document.createElement("h4");
    const pre = document.createElement("pre");
    heading.textContent = `${title} (${status})`;
    pre.textContent = content || "(empty)";
    pre.style.fontFamily = "monospace";
    pre.style.overflowX = "auto";
    pre.style.whiteSpace = "pre-wrap";
    wrapper.append(heading, pre);
    return wrapper;
  }

  function renderPreviewPane(): HTMLElement {
    const section = document.createElement("div");
    const heading = document.createElement("h3");
    heading.textContent = "Preview / diff";
    section.append(heading);

    if (!state.preview) {
      const placeholder = document.createElement("p");
      placeholder.textContent = "Preview a create, update, or delete to inspect the rendered diff and checks.";
      section.append(placeholder);
      return section;
    }

    const applyButton = document.createElement("button");
    applyButton.disabled = state.applying || !state.preview.can_apply || !state.previewRequest;
    applyButton.textContent = state.applying
      ? "Applying…"
      : state.preview.can_apply
        ? "Apply change"
        : "Apply blocked";
    applyButton.type = "button";
    applyButton.addEventListener("click", () => {
      void applyCurrentPreview();
    });

    const gateStatus = document.createElement("p");
    gateStatus.textContent = state.preview.can_apply
      ? "nginx validation passed — apply is enabled."
      : "nginx validation failed or is unavailable — apply is disabled.";

    section.append(gateStatus, applyButton);
    section.append(
      renderPreviewBlock("nginx -t", state.preview.nginx_test.output, state.preview.nginx_test.status),
      renderPreviewBlock("Gixy-Next", state.preview.gixy.output, state.preview.gixy.status),
      renderPreviewBlock("Unified diff", state.preview.diff, state.preview.diff ? "changes" : "no changes"),
      renderPreviewBlock("Rendered candidate config", state.preview.rendered, "rendered"),
    );
    return section;
  }

  function renderServiceEditor(): HTMLElement {
    const section = document.createElement("div");
    const form = document.createElement("form");
    const heading = document.createElement("h3");
    const kindSelect = document.createElement("select");
    const previewButton = document.createElement("button");

    heading.textContent = state.originalService ? `Edit ${state.originalService.name}` : "New service";
    section.append(heading);

    previewButton.textContent = state.originalService ? "Preview update" : "Preview create";
    previewButton.type = "submit";

    appendTextInput(form, "Name", state.form.name, (value) => {
      state.form.name = value;
      markPreviewStale();
    });
    appendTextInput(form, "Server name", state.form.serverName, (value) => {
      state.form.serverName = value;
      markPreviewStale();
    });

    const kindLabel = document.createElement("label");
    kindLabel.textContent = "Kind";
    kindSelect.append(new Option("proxy", "proxy"), new Option("static", "static"));
    kindSelect.value = state.form.kind;
    kindSelect.addEventListener("change", () => {
      state.form.kind = kindSelect.value === "static" ? "static" : "proxy";
      markPreviewStale();
      render();
    });
    form.append(kindLabel, document.createElement("br"), kindSelect, document.createElement("br"));

    if (state.form.kind === "proxy") {
      appendTextInput(form, "Upstream host", state.form.upstreamHost, (value) => {
        state.form.upstreamHost = value;
        markPreviewStale();
      });
      appendTextInput(form, "Upstream port", state.form.upstreamPort, (value) => {
        state.form.upstreamPort = value;
        markPreviewStale();
      }, "number");
      appendTextInput(form, "Upstream path", state.form.upstreamPath, (value) => {
        state.form.upstreamPath = value;
        markPreviewStale();
      });

      const schemeLabel = document.createElement("label");
      const schemeSelect = document.createElement("select");
      schemeLabel.textContent = "Upstream scheme";
      schemeSelect.append(new Option("http", "http"), new Option("https", "https"));
      schemeSelect.value = state.form.upstreamScheme;
      schemeSelect.addEventListener("change", () => {
        state.form.upstreamScheme = schemeSelect.value === "https" ? "https" : "http";
        markPreviewStale();
      });
      form.append(schemeLabel, document.createElement("br"), schemeSelect, document.createElement("br"));
    } else {
      appendTextInput(form, "Static root", state.form.staticRoot, (value) => {
        state.form.staticRoot = value;
        markPreviewStale();
      });
      appendTextInput(form, "Listing path", state.form.staticListingPath, (value) => {
        state.form.staticListingPath = value;
        markPreviewStale();
      });
    }

    appendTextArea(form, "Allow CIDRs (comma or newline separated)", state.form.allowCidrs, (value) => {
      state.form.allowCidrs = value;
      markPreviewStale();
    });
    appendCheckbox(form, "Forward Host header", state.form.forwardHostHeader, (checked) => {
      state.form.forwardHostHeader = checked;
      markPreviewStale();
    });
    appendCheckbox(form, "Disable gzip", state.form.gzipDisabled, (checked) => {
      state.form.gzipDisabled = checked;
      markPreviewStale();
    });
    appendCheckbox(form, "WebSocket upstream", state.form.websocket, (checked) => {
      state.form.websocket = checked;
      markPreviewStale();
    });

    if (state.originalService?.client_cert || state.originalService?.managed_by) {
      const preserved = document.createElement("p");
      preserved.textContent =
        "Advanced fields not shown here (for example client_cert or managed_by) will be preserved on save.";
      section.append(preserved);
    }

    const cancelButton = document.createElement("button");
    cancelButton.textContent = state.originalService ? "Cancel edit" : "Reset form";
    cancelButton.type = "button";
    cancelButton.addEventListener("click", () => {
      resetEditor();
      render();
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void previewCurrentForm();
    });
    form.append(previewButton, document.createTextNode(" "), cancelButton);
    section.append(form);
    return section;
  }

  function renderServiceList(): HTMLElement {
    const section = document.createElement("div");
    const heading = document.createElement("h3");
    heading.textContent = "Services";
    section.append(heading);

    if (state.loading) {
      const loading = document.createElement("p");
      loading.textContent = "Loading services…";
      section.append(loading);
      return section;
    }

    if (state.services.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No services found.";
      section.append(empty);
      return section;
    }

    const table = document.createElement("table");
    const headerRow = document.createElement("tr");
    for (const title of ["Name", "Server name", "Kind", "Actions"]) {
      const cell = document.createElement("th");
      cell.textContent = title;
      headerRow.append(cell);
    }
    table.append(headerRow);

    for (const service of state.services) {
      const row = document.createElement("tr");
      const nameCell = document.createElement("td");
      const serverCell = document.createElement("td");
      const kindCell = document.createElement("td");
      const actionsCell = document.createElement("td");
      const deleteButton = document.createElement("button");
      const editButton = document.createElement("button");

      nameCell.textContent = service.name;
      serverCell.textContent = service.server_name;
      kindCell.textContent = service.kind;

      editButton.textContent = "Edit";
      editButton.type = "button";
      editButton.addEventListener("click", () => {
        void beginEdit(service.name);
      });

      deleteButton.textContent = "Preview delete";
      deleteButton.type = "button";
      deleteButton.addEventListener("click", () => {
        void beginDelete(service.name);
      });

      actionsCell.append(editButton, document.createTextNode(" "), deleteButton);
      row.append(nameCell, serverCell, kindCell, actionsCell);
      table.append(row);
    }

    section.append(table);
    return section;
  }
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

function parseAllowCidrs(value: string): string[] {
  return value
    .split(/[\n,]/u)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

async function applyCatalogMutation(request: CatalogMutationRequest): Promise<ApplyResponse> {
  return fetchJson<ApplyResponse>("/catalog/apply", {
    body: JSON.stringify(request),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
}

async function previewCatalogMutation(request: CatalogMutationRequest): Promise<PreviewResponse> {
  return fetchJson<PreviewResponse>("/catalog/preview", {
    body: JSON.stringify(request),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
}

async function readCatalogService(name: string): Promise<ServiceEntry> {
  const response = await fetchJson<{ service: ServiceEntry }>(`/catalog/services/${encodeURIComponent(name)}`, {
    method: "GET",
  });
  return response.service;
}

async function readCatalogServices(): Promise<ServiceEntry[]> {
  const response = await fetchJson<{ services: ServiceEntry[] }>("/catalog/services", {
    method: "GET",
  });
  return response.services;
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

async function renderAppShell(root: HTMLElement): Promise<void> {
  const session = await readSession();
  if (!session) {
    window.location.assign(loginPath);
    return;
  }

  const heading = document.createElement("h1");
  const logoutButton = document.createElement("button");
  const shell = document.createElement("div");
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

  root.replaceChildren(heading, summary, logoutButton, shell);
  mountCatalogManager(shell);
}

function serviceToFormState(service: ServiceEntry): FormState {
  return {
    allowCidrs: (service.allow_cidrs ?? []).join("\n"),
    forwardHostHeader: service.forward_host_header === true,
    gzipDisabled: service.gzip === false,
    kind: service.kind,
    name: service.name,
    serverName: service.server_name,
    staticListingPath: service.static?.listing_path ?? "",
    staticRoot: service.static?.root ?? "",
    upstreamHost: service.upstream?.host ?? "",
    upstreamPath: service.upstream?.path ?? "/",
    upstreamPort: service.upstream ? String(service.upstream.port) : "8080",
    upstreamScheme: service.upstream?.scheme === "https" ? "https" : "http",
    websocket: service.websocket === true,
  };
}

function appendCheckbox(
  form: HTMLFormElement,
  labelText: string,
  checked: boolean,
  onChange: (checked: boolean) => void,
): void {
  const input = document.createElement("input");
  const label = document.createElement("label");

  input.checked = checked;
  input.type = "checkbox";
  input.addEventListener("change", () => {
    onChange(input.checked);
  });

  label.textContent = labelText;
  form.append(input, document.createTextNode(" "), label, document.createElement("br"));
}

function appendTextArea(
  form: HTMLFormElement,
  labelText: string,
  value: string,
  onChange: (value: string) => void,
): void {
  const label = document.createElement("label");
  const textarea = document.createElement("textarea");

  label.textContent = labelText;
  textarea.rows = 4;
  textarea.value = value;
  textarea.addEventListener("input", () => {
    onChange(textarea.value);
  });

  form.append(label, document.createElement("br"), textarea, document.createElement("br"));
}

function appendTextInput(
  form: HTMLFormElement,
  labelText: string,
  value: string,
  onChange: (value: string) => void,
  type = "text",
): void {
  const input = document.createElement("input");
  const label = document.createElement("label");

  input.type = type;
  input.value = value;
  input.addEventListener("input", () => {
    onChange(input.value);
  });

  label.textContent = labelText;
  form.append(label, document.createElement("br"), input, document.createElement("br"));
}

const root = document.getElementById("app");
if (root) {
  mountPage(root);
} else {
  console.error("home-warden: #app root element not found");
}
