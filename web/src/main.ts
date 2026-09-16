// Entry point for home-warden's admin web UI (#55 / #68 / #69 / #70).
//
// Still intentionally framework-free: plain DOM + fetch keeps the first UI
// issues small and inspectable while the backend contract settles.

// Injected by web/build.mjs's esbuild `define` at build time from
// `git rev-parse --short HEAD`; falls back to "unknown" if `.git` isn't
// available (e.g. a packaged checkout).
declare const __COMMIT_SHA__: string;

type AppView = "about" | "catalog" | "health";
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
type DashboardState = {
  data: HealthResponse | null;
  error: string | null;
  lastUpdatedLabel: string | null;
  loading: boolean;
  refreshing: boolean;
};
type HealthCheck = {
  detail: string;
  dimension: "cert" | "dns" | "upstream";
  service: string;
  status: "fail" | "ok" | "skip";
};
type HealthGroup = {
  checks: Record<HealthCheck["dimension"], HealthCheck | null>;
  service: string;
};
type HealthResponse = {
  checks: HealthCheck[];
  healthy: boolean;
};

const appPath = "/";
const appCopyright = "Copyright © 2026 Henrique Andrade";
const appLicense = "MIT License";
const appLogo = "🛡️";
const appRepoUrl = "https://github.com/the-hcma/home-warden";
const appVersion = "0.1.0";
const healthPollIntervalMs = 30_000;
const loginPath = "/login";

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

async function applyCatalogMutation(request: CatalogMutationRequest): Promise<ApplyResponse> {
  return fetchJson<ApplyResponse>("/catalog/apply", {
    body: JSON.stringify(request),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
}

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

function buildStatusBadge(status: HealthCheck["status"]): HTMLElement {
  const badge = document.createElement("span");

  badge.textContent = status.toUpperCase();
  badge.classList.add("badge");
  styleStatusBadge(badge, status);
  return badge;
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

function extractCertDomain(check: HealthCheck): string | null {
  const coverPrefix = "SANs cover ";
  const coverIndex = check.detail.indexOf(coverPrefix);
  if (coverIndex >= 0) {
    return check.detail.slice(coverIndex + coverPrefix.length).trim() || null;
  }

  const missingPathMatch = /\/live\/([^/]+)\/fullchain\.pem/u.exec(check.detail);
  if (missingPathMatch?.[1]) {
    return missingPathMatch[1];
  }

  const sanFailureMatch = /^([^ ]+) not covered by cert SANs/u.exec(check.detail);
  if (sanFailureMatch?.[1]) {
    return sanFailureMatch[1];
  }

  return null;
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

function groupHealthChecks(checks: HealthCheck[]): HealthGroup[] {
  const groups = new Map<string, HealthGroup>();

  for (const check of checks) {
    let group = groups.get(check.service);
    if (!group) {
      group = {
        checks: {
          cert: null,
          dns: null,
          upstream: null,
        },
        service: check.service,
      };
      groups.set(check.service, group);
    }
    group.checks[check.dimension] = check;
  }

  return Array.from(groups.values()).sort((left, right) => left.service.localeCompare(right.service));
}

function inferRenewalState(check: HealthCheck): string {
  if (check.status === "skip") {
    return "Not configured";
  }

  const expiry = parseExpiryDate(check.detail);
  if (check.status === "ok") {
    if (!expiry) {
      return "Healthy";
    }
    const daysLeft = Math.ceil((expiry.getTime() - Date.now()) / 86_400_000);
    return daysLeft >= 0 ? `Healthy (${daysLeft}d left)` : `Expired ${Math.abs(daysLeft)}d ago`;
  }

  if (check.detail.startsWith("expires within ")) {
    if (!expiry) {
      return "Renewal due soon";
    }
    const daysLeft = Math.ceil((expiry.getTime() - Date.now()) / 86_400_000);
    return daysLeft >= 0 ? `Renew soon (${daysLeft}d left)` : `Expired ${Math.abs(daysLeft)}d ago`;
  }

  return "Action needed";
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

function mountAboutPanel(root: HTMLElement, username: string): () => void {
  const card = document.createElement("div");
  const heading = document.createElement("h2");
  const description = document.createElement("p");
  const facts = document.createElement("p");
  const repoLink = document.createElement("a");
  const licenseLink = document.createElement("a");
  const commitLink = document.createElement("a");

  heading.textContent = `${appLogo} home-warden`;
  description.textContent =
    "A self-hosted nginx reverse proxy + certbot runner for home services, managed through this admin UI.";

  repoLink.href = appRepoUrl;
  repoLink.rel = "noopener noreferrer";
  repoLink.target = "_blank";
  repoLink.textContent = appRepoUrl.replace("https://", "");

  licenseLink.href = `${appRepoUrl}/blob/main/LICENSE`;
  licenseLink.rel = "noopener noreferrer";
  licenseLink.target = "_blank";
  licenseLink.textContent = appLicense;

  const commitSha = __COMMIT_SHA__;
  const commitNode: Node = document.createTextNode(commitSha);
  if (commitSha !== "unknown") {
    commitLink.href = `${appRepoUrl}/commit/${commitSha}`;
    commitLink.rel = "noopener noreferrer";
    commitLink.target = "_blank";
    commitLink.textContent = commitSha;
  }

  facts.append(
    `Version ${appVersion} (`,
    commitSha === "unknown" ? commitNode : commitLink,
    `)`,
    document.createElement("br"),
    "Repository: ",
    repoLink,
    document.createElement("br"),
    "License: ",
    licenseLink,
    document.createElement("br"),
    appCopyright,
    document.createElement("br"),
    `Signed in as ${username}.`,
  );

  card.append(heading, description, facts);
  styleSection(card);
  root.replaceChildren(card);

  return () => {
    root.replaceChildren();
  };
}

function mountAppShell(root: HTMLElement): void {
  renderAppShell(root).catch((error: unknown) => {
    // readSession()/logout() throw on a 500/503 or a dropped connection --
    // without this catch the rejection was silently swallowed, leaving the
    // operator staring at an empty #app with no message and no redirect.
    console.error("home-warden: failed to render app shell", error);
    const message = error instanceof Error ? error.message : "Failed to load session";
    const errorNode = document.createElement("p");
    errorNode.classList.add("error-banner");
    errorNode.textContent = message;
    root.replaceChildren(errorNode);
  });
}

function mountCatalogManager(root: HTMLElement): () => void {
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
  let actionsHost: HTMLDivElement | null = null;
  let disposed = false;
  let previewHost: HTMLElement | null = null;

  render();
  void refreshServices().finally(() => {
    safeRender();
  });

  return () => {
    disposed = true;
    root.replaceChildren();
  };

  async function applyCurrentPreview(): Promise<void> {
    if (state.applying || !state.previewRequest || disposed) {
      return;
    }

    state.applying = true;
    state.error = null;
    state.message = "Applying catalog change…";
    safeRender();
    try {
      const result = await applyCatalogMutation(state.previewRequest);
      if (disposed) {
        return;
      }
      if (result.deleted_name) {
        resetEditor();
        state.message = `Deleted ${result.deleted_name}.`;
      } else if (result.service) {
        invalidatePreview();
        state.form = serviceToFormState(result.service);
        state.message = `Applied ${result.service.name}.`;
        state.originalService = result.service;
      } else {
        invalidatePreview();
        state.message = "Applied catalog change.";
      }
      const refreshPromise = refreshServices();
      safeRender();
      await refreshPromise;
      if (disposed) {
        return;
      }
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Apply failed";
    } finally {
      state.applying = false;
    }
    safeRender();
  }

  function beginCreate(): void {
    if (disposed) {
      return;
    }
    state.error = null;
    state.message = "Creating a new service.";
    resetEditor();
    safeRender();
  }

  async function beginDelete(name: string): Promise<void> {
    if (disposed) {
      return;
    }
    state.error = null;
    state.message = `Previewing deletion of ${name}…`;
    invalidatePreview();
    safeRender();

    try {
      const request: CatalogMutationRequest = { action: "delete", name };
      const preview = await previewCatalogMutation(request);
      if (disposed) {
        return;
      }
      state.message = `Preview ready for deleting ${name}.`;
      state.preview = preview;
      state.previewRequest = request;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Preview failed";
    }
    safeRender();
  }

  async function beginEdit(name: string): Promise<void> {
    if (disposed) {
      return;
    }
    state.error = null;
    state.message = `Loading ${name}…`;
    invalidatePreview();
    safeRender();

    try {
      const service = await readCatalogService(name);
      if (disposed) {
        return;
      }
      state.form = serviceToFormState(service);
      state.message = `Editing ${name}.`;
      state.originalService = service;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Failed to load service";
    }
    safeRender();
  }

  function invalidatePreview(): void {
    state.preview = null;
    state.previewRequest = null;
  }

  function markPreviewStale(): void {
    const hadPreview = state.preview !== null || state.previewRequest !== null;
    invalidatePreview();
    if (hadPreview) {
      state.message = "Form changed — preview again before applying.";
      refreshCatalogChrome();
    }
  }

  async function previewCurrentForm(): Promise<void> {
    if (disposed) {
      return;
    }
    state.error = null;
    state.message = "Rendering preview…";
    invalidatePreview();
    safeRender();

    try {
      const nextService = buildServiceFromForm(state.form, state.originalService, state.originalService !== null);
      const request: CatalogMutationRequest = state.originalService
        ? { action: "update", name: state.originalService.name, service: nextService }
        : { action: "create", service: nextService };
      const preview = await previewCatalogMutation(request);
      if (disposed) {
        return;
      }
      state.message = `Preview ready for ${nextService.name || "this service"}.`;
      state.preview = preview;
      state.previewRequest = request;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Preview failed";
    }
    safeRender();
  }

  async function refreshServices(): Promise<void> {
    state.loading = true;
    state.error = null;
    try {
      const services = await readCatalogServices();
      if (disposed) {
        return;
      }
      state.services = services;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Failed to load services";
      state.services = [];
    }
    state.loading = false;
  }

  function refreshCatalogChrome(): void {
    if (disposed) {
      return;
    }

    const nextActions = renderActions();
    const nextPreview = renderPreviewSection();

    if (actionsHost) {
      actionsHost.replaceWith(nextActions);
    }
    if (previewHost) {
      previewHost.replaceWith(nextPreview);
    }
    actionsHost = nextActions;
    previewHost = nextPreview;
  }

  function render(): void {
    const actions = renderActions();
    const container = document.createElement("div");
    const editorSection = document.createElement("section");
    const layout = document.createElement("div");
    const listSection = document.createElement("section");
    const previewSection = renderPreviewSection();

    editorSection.append(renderServiceEditor());
    listSection.append(renderServiceList());
    styleSection(editorSection);
    styleSection(listSection);

    layout.classList.add("catalog-layout");
    layout.append(listSection, editorSection, previewSection);

    actionsHost = actions;
    previewHost = previewSection;
    container.append(actions, layout);
    root.replaceChildren(container);
  }

  function renderActions(): HTMLDivElement {
    const actions = document.createElement("div");
    const heading = document.createElement("h2");

    heading.textContent = "Service catalog";
    actions.append(heading);

    const addButton = document.createElement("button");
    addButton.textContent = "Add service";
    addButton.type = "button";
    addButton.addEventListener("click", () => {
      beginCreate();
    });
    actions.append(addButton);

    if (state.message) {
      const messageNode = document.createElement("p");
      messageNode.classList.add("message");
      messageNode.textContent = state.message;
      actions.append(messageNode);
    }
    if (state.error) {
      const errorNode = document.createElement("p");
      errorNode.classList.add("error-banner");
      errorNode.textContent = state.error;
      actions.append(errorNode);
    }

    return actions;
  }

  function renderPreviewBlock(title: string, content: string, status: string): HTMLElement {
    const heading = document.createElement("h4");
    const pre = document.createElement("pre");
    const wrapper = document.createElement("div");

    heading.textContent = `${title} (${status})`;
    pre.textContent = content || "(empty)";
    pre.classList.add("code-block");
    wrapper.append(heading, pre);
    return wrapper;
  }

  function renderPreviewPane(): HTMLElement {
    const heading = document.createElement("h3");
    const section = document.createElement("div");

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
    gateStatus.classList.add(state.preview.can_apply ? "status-ok" : "status-fail");
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

  function renderPreviewSection(): HTMLElement {
    const previewSection = document.createElement("section");
    previewSection.append(renderPreviewPane());
    styleSection(previewSection);
    return previewSection;
  }

  function renderServiceEditor(): HTMLElement {
    const form = document.createElement("form");
    const heading = document.createElement("h3");
    const kindSelect = document.createElement("select");
    const previewButton = document.createElement("button");
    const section = document.createElement("div");

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
      safeRender();
    });
    form.append(kindLabel, document.createElement("br"), kindSelect, document.createElement("br"));

    if (state.form.kind === "proxy") {
      appendTextInput(form, "Upstream host", state.form.upstreamHost, (value) => {
        state.form.upstreamHost = value;
        markPreviewStale();
      });
      appendTextInput(
        form,
        "Upstream port",
        state.form.upstreamPort,
        (value) => {
          state.form.upstreamPort = value;
          markPreviewStale();
        },
        "number",
      );
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
      safeRender();
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
    const heading = document.createElement("h3");
    const section = document.createElement("div");

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

    styleTable(table);
    for (const title of ["Name", "Server name", "Kind", "Actions"]) {
      const cell = document.createElement("th");
      cell.textContent = title;
      styleTableCell(cell, true);
      headerRow.append(cell);
    }
    table.append(headerRow);

    for (const service of state.services) {
      const actionsCell = document.createElement("td");
      const deleteButton = document.createElement("button");
      const editButton = document.createElement("button");
      const kindCell = document.createElement("td");
      const nameCell = document.createElement("td");
      const row = document.createElement("tr");
      const serverCell = document.createElement("td");

      kindCell.textContent = service.kind;
      nameCell.textContent = service.name;
      serverCell.textContent = service.server_name;
      styleTableCell(actionsCell);
      styleTableCell(kindCell);
      styleTableCell(nameCell);
      styleTableCell(serverCell);

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

  function resetEditor(): void {
    state.form = blankFormState();
    state.originalService = null;
    invalidatePreview();
  }

  function safeRender(): void {
    if (!disposed) {
      render();
    }
  }
}

function mountHealthDashboard(root: HTMLElement): () => void {
  const state: DashboardState = {
    data: null,
    error: null,
    lastUpdatedLabel: null,
    loading: true,
    refreshing: false,
  };
  let disposed = false;
  let intervalId: number | null = null;
  let requestVersion = 0;
  let requestInFlight = false;

  void refreshHealth("initial");
  intervalId = window.setInterval(() => {
    // Skip this poll tick rather than starting an overlapping request: /health/catalog
    // can legitimately take longer than healthPollIntervalMs (DNS checks retry with
    // backoff), and letting requests pile up means every response keeps getting
    // superseded before it lands, leaving the dashboard stuck on "Loading" forever.
    if (requestInFlight) {
      return;
    }
    void refreshHealth("poll");
  }, healthPollIntervalMs);
  render();

  return () => {
    disposed = true;
    if (intervalId !== null) {
      window.clearInterval(intervalId);
      intervalId = null;
    }
    root.replaceChildren();
  };

  async function refreshHealth(source: "initial" | "manual" | "poll"): Promise<void> {
    const currentRequest = requestVersion + 1;
    const hasData = state.data !== null;

    requestVersion = currentRequest;
    requestInFlight = true;
    state.error = null;
    state.loading = !hasData;
    state.refreshing = hasData;
    safeRender();

    try {
      const data = await readCatalogHealth();
      if (disposed || currentRequest !== requestVersion) {
        return;
      }
      state.data = data;
      state.error = null;
      state.lastUpdatedLabel = new Date().toLocaleString();
    } catch (error: unknown) {
      if (disposed || currentRequest !== requestVersion) {
        return;
      }
      const message = error instanceof Error ? error.message : "Failed to load health data";
      state.error = hasData && source !== "initial" ? `Refresh failed: ${message}` : message;
    } finally {
      if (currentRequest === requestVersion) {
        requestInFlight = false;
      }
    }

    if (disposed || currentRequest !== requestVersion) {
      return;
    }
    state.loading = false;
    state.refreshing = false;
    safeRender();
  }

  function render(): void {
    const container = document.createElement("div");
    const controls = document.createElement("div");
    const heading = document.createElement("h2");
    const refreshButton = document.createElement("button");

    heading.textContent = "Health dashboard";
    controls.append(heading);

    refreshButton.disabled = state.loading || state.refreshing;
    refreshButton.textContent = state.refreshing ? "Refreshing…" : "Refresh now";
    refreshButton.type = "button";
    refreshButton.addEventListener("click", () => {
      void refreshHealth("manual");
    });
    controls.append(refreshButton);

    const cadence = document.createElement("p");
    cadence.classList.add("message");
    cadence.textContent = state.lastUpdatedLabel
      ? `Auto-refreshes every 30s. Last updated ${state.lastUpdatedLabel}.`
      : "Auto-refreshes every 30s.";
    controls.append(cadence);

    if (state.error) {
      const errorNode = document.createElement("p");
      errorNode.classList.add("error-banner");
      errorNode.textContent = state.data ? `${state.error}. Showing last successful response.` : state.error;
      controls.append(errorNode);
    }

    if (state.loading && !state.data) {
      const loadingNode = document.createElement("p");
      loadingNode.textContent = "Loading health checks…";
      container.append(controls, loadingNode);
      root.replaceChildren(container);
      return;
    }

    if (!state.data) {
      const emptyNode = document.createElement("p");
      emptyNode.textContent = "Health data is not available yet.";
      container.append(controls, emptyNode);
      root.replaceChildren(container);
      return;
    }

    container.append(
      controls,
      renderHealthSummary(state.data),
      renderServiceDashboard(state.data),
      renderCertificatePanel(state.data),
    );
    root.replaceChildren(container);
  }

  function renderCertificatePanel(data: HealthResponse): HTMLElement {
    const certChecks = data.checks
      .filter((check) => check.dimension === "cert")
      .sort((left, right) => left.service.localeCompare(right.service));
    const section = document.createElement("section");
    const heading = document.createElement("h3");

    heading.textContent = "Certificates";
    section.append(heading);
    styleSection(section);

    if (certChecks.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No server-certificate checks were returned.";
      section.append(empty, renderClientCertPlaceholder());
      return section;
    }

    const table = document.createElement("table");
    const headerRow = document.createElement("tr");

    styleTable(table);
    for (const title of ["Service", "Domain", "Status", "Renewal", "Detail"]) {
      const cell = document.createElement("th");
      cell.textContent = title;
      styleTableCell(cell, true);
      headerRow.append(cell);
    }
    table.append(headerRow);

    for (const check of certChecks) {
      const detailCell = document.createElement("td");
      const domainCell = document.createElement("td");
      const renewalCell = document.createElement("td");
      const row = document.createElement("tr");
      const serviceCell = document.createElement("td");
      const statusCell = document.createElement("td");

      detailCell.textContent = check.detail;
      domainCell.textContent = extractCertDomain(check) ?? "Unavailable from current API response";
      renewalCell.textContent = inferRenewalState(check);
      serviceCell.textContent = check.service;
      statusCell.append(buildStatusBadge(check.status));
      styleTableCell(detailCell);
      styleTableCell(domainCell);
      styleTableCell(renewalCell);
      styleTableCell(serviceCell);
      styleTableCell(statusCell);

      row.append(serviceCell, domainCell, statusCell, renewalCell, detailCell);
      table.append(row);
    }

    section.append(table, renderClientCertPlaceholder());
    return section;
  }

  function renderCheckCell(check: HealthCheck | null): HTMLElement {
    const wrapper = document.createElement("div");

    if (!check) {
      wrapper.textContent = "No check returned.";
      return wrapper;
    }

    const detail = document.createElement("p");
    detail.textContent = check.detail;
    detail.classList.add("check-detail");

    wrapper.append(buildStatusBadge(check.status), detail);
    return wrapper;
  }

  function renderClientCertPlaceholder(): HTMLElement {
    const heading = document.createElement("h4");
    const note = document.createElement("p");
    const section = document.createElement("div");

    heading.textContent = "Client-cert / CRL status";
    note.textContent = "Coming soon — placeholder for #49's client-cert and CRL observability.";
    section.append(heading, note);
    return section;
  }

  function renderHealthSummary(data: HealthResponse): HTMLElement {
    const groups = groupHealthChecks(data.checks);
    const failCount = data.checks.filter((check) => check.status === "fail").length;
    const healthyServices = groups.filter(
      (group) => !Object.values(group.checks).some((check) => check?.status === "fail"),
    ).length;
    const section = document.createElement("section");
    const heading = document.createElement("h3");
    const summary = document.createElement("p");
    const totals = document.createElement("p");

    heading.textContent = data.healthy ? "Overall status: healthy" : "Overall status: attention needed";
    summary.textContent =
      groups.length > 0
        ? `${healthyServices}/${groups.length} services have no failing checks.`
        : "No services were returned by /health/catalog.";

    const okCount = data.checks.filter((check) => check.status === "ok").length;
    const skipCount = data.checks.filter((check) => check.status === "skip").length;
    totals.textContent = `${okCount} ok, ${failCount} fail, ${skipCount} skip across ${data.checks.length} checks.`;

    section.append(heading, summary, totals);
    styleSection(section);
    return section;
  }

  function renderServiceDashboard(data: HealthResponse): HTMLElement {
    const groups = groupHealthChecks(data.checks);
    const section = document.createElement("section");
    const heading = document.createElement("h3");

    heading.textContent = "Per-service checks";
    section.append(heading);
    styleSection(section);

    if (groups.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No service checks were returned.";
      section.append(empty);
      return section;
    }

    const table = document.createElement("table");
    const headerRow = document.createElement("tr");

    styleTable(table);
    for (const title of ["Service", "Cert", "DNS", "Upstream"]) {
      const cell = document.createElement("th");
      cell.textContent = title;
      styleTableCell(cell, true);
      headerRow.append(cell);
    }
    table.append(headerRow);

    for (const group of groups) {
      const certCell = document.createElement("td");
      const dnsCell = document.createElement("td");
      const row = document.createElement("tr");
      const serviceCell = document.createElement("td");
      const upstreamCell = document.createElement("td");

      certCell.append(renderCheckCell(group.checks.cert));
      dnsCell.append(renderCheckCell(group.checks.dns));
      serviceCell.textContent = group.service;
      upstreamCell.append(renderCheckCell(group.checks.upstream));
      styleTableCell(certCell);
      styleTableCell(dnsCell);
      styleTableCell(serviceCell);
      styleTableCell(upstreamCell);

      row.append(serviceCell, certCell, dnsCell, upstreamCell);
      table.append(row);
    }

    section.append(table);
    return section;
  }

  function safeRender(): void {
    if (!disposed) {
      render();
    }
  }
}

function mountLoginForm(root: HTMLElement): void {
  root.classList.add("login-shell");
  let errorNode: HTMLParagraphElement | null = null;

  const heading = document.createElement("h1");
  heading.textContent = `${appLogo} home-warden login`;

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
        errorNode.classList.add("error-banner");
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

function parseExpiryDate(detail: string): Date | null {
  const match = /notAfter=([^); ]+)/u.exec(detail);

  if (!match?.[1]) {
    return null;
  }

  const expiry = new Date(match[1]);
  return Number.isNaN(expiry.getTime()) ? null : expiry;
}

async function previewCatalogMutation(request: CatalogMutationRequest): Promise<PreviewResponse> {
  return fetchJson<PreviewResponse>("/catalog/preview", {
    body: JSON.stringify(request),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
}

async function readCatalogHealth(): Promise<HealthResponse> {
  return fetchJson<HealthResponse>("/health/catalog", {
    method: "GET",
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
  const username = session.username;

  const content = document.createElement("div");
  const heading = document.createElement("h1");
  const menu = document.createElement("div");
  const menuButton = document.createElement("button");
  const menuPanel = document.createElement("div");
  const shell = document.createElement("div");
  const summary = document.createElement("p");
  const toolbar = document.createElement("div");
  let activeView: AppView = "health";
  let logoutErrorNode: HTMLParagraphElement | null = null;
  let unmountCurrentView: (() => void) | null = null;

  heading.textContent = `${appLogo} home-warden`;
  summary.textContent = `Signed in as ${username}.`;

  const aboutButton = document.createElement("button");
  const catalogButton = document.createElement("button");
  const healthButton = document.createElement("button");
  const logoutButton = document.createElement("button");

  aboutButton.textContent = "About";
  aboutButton.type = "button";
  aboutButton.addEventListener("click", () => {
    mountView("about");
    closeMenu();
  });

  catalogButton.textContent = "Catalog";
  catalogButton.type = "button";
  catalogButton.addEventListener("click", () => {
    mountView("catalog");
    closeMenu();
  });

  healthButton.textContent = "Health dashboard";
  healthButton.type = "button";
  healthButton.addEventListener("click", () => {
    mountView("health");
    closeMenu();
  });

  logoutButton.textContent = "Log out";
  logoutButton.type = "button";
  logoutButton.addEventListener("click", () => {
    logoutButton.disabled = true;
    logout()
      .then(() => {
        unmountCurrentView?.();
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : "Log out failed";
        logoutErrorNode?.remove();
        logoutErrorNode = document.createElement("p");
        logoutErrorNode.classList.add("error-banner");
        logoutErrorNode.textContent = message;
        root.append(logoutErrorNode);
      })
      .finally(() => {
        logoutButton.disabled = false;
      });
  });

  menuButton.classList.add("menu-button");
  menuButton.textContent = "☰";
  menuButton.type = "button";
  menuButton.setAttribute("aria-expanded", "false");
  menuButton.setAttribute("aria-label", "Menu");
  menuButton.addEventListener("click", () => {
    setMenuOpen(Boolean(menuPanel.hidden));
  });

  menuPanel.classList.add("menu-panel");
  menuPanel.hidden = true;
  menuPanel.append(healthButton, catalogButton, aboutButton);

  menu.classList.add("menu");
  menu.append(menuButton, menuPanel);

  // Close the menu on an outside click -- registered once here rather than
  // added/removed per open/close so there's nothing to leak on unmount.
  document.addEventListener("click", (event) => {
    if (!menuPanel.hidden && !menu.contains(event.target as Node)) {
      setMenuOpen(false);
    }
  });

  const headerBar = document.createElement("div");
  headerBar.classList.add("header-bar");
  headerBar.append(menu, heading, logoutButton);

  toolbar.classList.add("toolbar");
  content.append(summary);
  toolbar.append(headerBar, content);

  root.replaceChildren(toolbar, shell);
  mountView(activeView);

  function closeMenu(): void {
    setMenuOpen(false);
  }

  function setMenuOpen(open: boolean): void {
    menuPanel.hidden = !open;
    menuButton.setAttribute("aria-expanded", String(open));
  }

  function mountView(view: AppView): void {
    if (activeView === view && unmountCurrentView) {
      return;
    }

    unmountCurrentView?.();
    activeView = view;
    aboutButton.disabled = activeView === "about";
    catalogButton.disabled = activeView === "catalog";
    healthButton.disabled = activeView === "health";
    unmountCurrentView =
      activeView === "catalog"
        ? mountCatalogManager(shell)
        : activeView === "about"
          ? mountAboutPanel(shell, username)
          : mountHealthDashboard(shell);
  }
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

function styleSection(section: HTMLElement): void {
  section.classList.add("card");
}

function styleStatusBadge(node: HTMLElement, status: HealthCheck["status"]): void {
  switch (status) {
    case "fail":
      node.classList.add("badge--fail");
      return;
    case "ok":
      node.classList.add("badge--ok");
      return;
    case "skip":
      node.classList.add("badge--skip");
      return;
  }
}

function styleTable(table: HTMLTableElement): void {
  table.classList.add("table");
}

function styleTableCell(cell: HTMLTableCellElement, header = false): void {
  cell.classList.add("table__cell");
  if (header) {
    cell.classList.add("table__cell--header");
  }
}

const root = document.getElementById("app");
if (root) {
  mountPage(root);
} else {
  console.error("home-warden: #app root element not found");
}
