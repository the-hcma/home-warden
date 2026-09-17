// Entry point for home-warden's admin web UI (#55 / #68 / #69 / #70).
//
// Still intentionally framework-free: plain DOM + fetch keeps the first UI
// issues small and inspectable while the backend contract settles.

// Injected by web/build.mjs's esbuild `define` at build time from
// `git rev-parse --short HEAD`; falls back to "unknown" if `.git` isn't
// available (e.g. a packaged checkout).
declare const __COMMIT_SHA__: string;

type AppView = "about" | "catalog" | "health" | "settings";
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
  forward_client_ip?: boolean | null;
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
type StreamUpstreamConfig = JsonObject & {
  host: string;
  port: number;
};
type StreamEntry = JsonObject & {
  listen_port: number;
  name: string;
  upstream: StreamUpstreamConfig;
};
type CatalogEntityKind = "service" | "stream";
type CatalogMutationRequest = {
  action: CatalogAction;
  name?: string;
  service?: JsonObject;
  target?: CatalogEntityKind;
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
  stream?: StreamEntry;
};
type SmtpConfigOut = {
  from_address: string;
  host: string;
  mail_domain: string;
  password_configured: boolean;
  port: number;
  username: string;
};
type SmtpConfigIn = {
  from_address: string;
  host: string;
  mail_domain: string;
  password: null | string;
  port: number;
  username: string;
};
type SmtpTestEmailIn = SmtpConfigIn & { to_address: string };
type SmtpTestEmailOut = {
  message: string;
  ok: boolean;
};
type SmtpSettingsFormState = {
  fromAddress: string;
  host: string;
  mailDomain: string;
  password: string;
  port: string;
  username: string;
};
type SmtpSettingsState = {
  deleting: boolean;
  error: string | null;
  existing: null | SmtpConfigOut;
  form: SmtpSettingsFormState;
  loading: boolean;
  message: string | null;
  saving: boolean;
  testPassed: boolean;
  testRecipient: string;
  testing: boolean;
};
type FormState = {
  allowCidrs: string;
  forwardClientIp: boolean;
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
type StreamFormState = {
  listenPort: string;
  name: string;
  upstreamHost: string;
  upstreamPort: string;
};
type CatalogState = {
  activeEntity: CatalogEntityKind;
  applying: boolean;
  error: string | null;
  form: FormState;
  loading: boolean;
  loadingStreams: boolean;
  message: string | null;
  originalService: ServiceEntry | null;
  originalStream: StreamEntry | null;
  preview: PreviewResponse | null;
  previewRequest: CatalogMutationRequest | null;
  services: ServiceEntry[];
  streamForm: StreamFormState;
  streams: StreamEntry[];
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
    forwardClientIp: false,
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

function blankStreamFormState(): StreamFormState {
  return {
    listenPort: "",
    name: "",
    upstreamHost: "",
    upstreamPort: "",
  };
}

function buildStreamFromForm(form: StreamFormState): StreamEntry {
  return {
    listen_port: Number(form.listenPort),
    name: form.name.trim(),
    upstream: {
      host: form.upstreamHost.trim(),
      port: Number(form.upstreamPort),
    },
  };
}

function streamToFormState(stream: StreamEntry): StreamFormState {
  return {
    listenPort: String(stream.listen_port),
    name: stream.name,
    upstreamHost: stream.upstream.host,
    upstreamPort: String(stream.upstream.port),
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

  if (form.forwardClientIp) {
    service.forward_client_ip = true;
  } else if (forUpdate) {
    service.forward_client_ip = null;
  } else {
    delete service.forward_client_ip;
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

function renderDomainLink(domain: null | string, fallback: string): Node {
  const trimmed = domain?.trim();
  if (!trimmed) {
    return document.createTextNode(fallback);
  }

  // home-warden terminates TLS for every proxied/static service, so a bare
  // server_name/domain is always reachable over https.
  const link = document.createElement("a");
  link.href = `https://${trimmed}`;
  link.rel = "noopener noreferrer";
  link.target = "_blank";
  link.textContent = trimmed;
  return link;
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
    activeEntity: "service",
    applying: false,
    error: null,
    form: blankFormState(),
    loading: true,
    loadingStreams: true,
    message: null,
    originalService: null,
    originalStream: null,
    preview: null,
    previewRequest: null,
    services: [],
    streamForm: blankStreamFormState(),
    streams: [],
  };
  let actionsHost: HTMLDivElement | null = null;
  let disposed = false;
  let previewHost: HTMLElement | null = null;

  render();
  void refreshServices().finally(() => {
    safeRender();
  });
  void refreshStreams().finally(() => {
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

    const target = state.previewRequest.target ?? "service";
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
        if (target === "stream") {
          resetStreamEditor();
        } else {
          resetEditor();
        }
        state.message = `Deleted ${result.deleted_name}.`;
      } else if (result.stream) {
        invalidatePreview();
        state.streamForm = streamToFormState(result.stream);
        state.message = `Applied ${result.stream.name}.`;
        state.originalStream = result.stream;
      } else if (result.service) {
        invalidatePreview();
        state.form = serviceToFormState(result.service);
        state.message = `Applied ${result.service.name}.`;
        state.originalService = result.service;
      } else {
        invalidatePreview();
        state.message = "Applied catalog change.";
      }
      const refreshPromise = target === "stream" ? refreshStreams() : refreshServices();
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

  function beginCreateStream(): void {
    if (disposed) {
      return;
    }
    state.error = null;
    state.message = "Creating a new stream.";
    resetStreamEditor();
    safeRender();
  }

  async function beginDelete(name: string): Promise<void> {
    if (disposed) {
      return;
    }
    state.activeEntity = "service";
    state.error = null;
    state.message = `Previewing deletion of ${name}…`;
    invalidatePreview();
    safeRender();

    try {
      const request: CatalogMutationRequest = { action: "delete", name, target: "service" };
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

  async function beginDeleteStream(name: string): Promise<void> {
    if (disposed) {
      return;
    }
    state.activeEntity = "stream";
    state.error = null;
    state.message = `Previewing deletion of ${name}…`;
    invalidatePreview();
    safeRender();

    try {
      const request: CatalogMutationRequest = { action: "delete", name, target: "stream" };
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
    state.activeEntity = "service";
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

  async function beginEditStream(name: string): Promise<void> {
    if (disposed) {
      return;
    }
    state.activeEntity = "stream";
    state.error = null;
    state.message = `Loading ${name}…`;
    invalidatePreview();
    safeRender();

    try {
      const stream = await readCatalogStream(name);
      if (disposed) {
        return;
      }
      state.streamForm = streamToFormState(stream);
      state.message = `Editing ${name}.`;
      state.originalStream = stream;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Failed to load stream";
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
    state.activeEntity = "service";
    state.error = null;
    state.message = "Rendering preview…";
    invalidatePreview();
    safeRender();

    try {
      const nextService = buildServiceFromForm(state.form, state.originalService, state.originalService !== null);
      const request: CatalogMutationRequest = state.originalService
        ? { action: "update", name: state.originalService.name, service: nextService, target: "service" }
        : { action: "create", service: nextService, target: "service" };
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

  async function previewCurrentStreamForm(): Promise<void> {
    if (disposed) {
      return;
    }
    state.activeEntity = "stream";
    state.error = null;
    state.message = "Rendering preview…";
    invalidatePreview();
    safeRender();

    try {
      const nextStream = buildStreamFromForm(state.streamForm);
      const request: CatalogMutationRequest = state.originalStream
        ? { action: "update", name: state.originalStream.name, service: nextStream, target: "stream" }
        : { action: "create", service: nextStream, target: "stream" };
      const preview = await previewCatalogMutation(request);
      if (disposed) {
        return;
      }
      state.message = `Preview ready for ${nextStream.name || "this stream"}.`;
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

  async function refreshStreams(): Promise<void> {
    state.loadingStreams = true;
    state.error = null;
    try {
      const streams = await readCatalogStreams();
      if (disposed) {
        return;
      }
      state.streams = streams;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Failed to load streams";
      state.streams = [];
    }
    state.loadingStreams = false;
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
    const streamActions = renderStreamActions();
    const streamEditorSection = document.createElement("section");
    const streamLayout = document.createElement("div");
    const streamListSection = document.createElement("section");
    const previewSection = renderPreviewSection();

    editorSection.append(renderServiceEditor());
    listSection.append(renderServiceList());
    styleSection(editorSection);
    styleSection(listSection);

    layout.classList.add("catalog-layout");
    layout.append(listSection, editorSection);

    streamEditorSection.append(renderStreamEditor());
    streamListSection.append(renderStreamList());
    styleSection(streamEditorSection);
    styleSection(streamListSection);

    streamLayout.classList.add("catalog-layout");
    streamLayout.append(streamListSection, streamEditorSection);

    actionsHost = actions;
    previewHost = previewSection;
    container.append(actions, layout, streamActions, streamLayout, previewSection);
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

  function renderStreamActions(): HTMLDivElement {
    const actions = document.createElement("div");
    const heading = document.createElement("h2");

    heading.textContent = "Streams (TCP passthrough)";
    actions.append(heading);

    const addButton = document.createElement("button");
    addButton.textContent = "Add stream";
    addButton.type = "button";
    addButton.addEventListener("click", () => {
      beginCreateStream();
    });
    actions.append(addButton);

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
    appendCheckbox(form, "Forward client IP (X-Forwarded-For)", state.form.forwardClientIp, (checked) => {
      state.form.forwardClientIp = checked;
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

  function renderStreamEditor(): HTMLElement {
    const form = document.createElement("form");
    const heading = document.createElement("h3");
    const previewButton = document.createElement("button");
    const section = document.createElement("div");

    heading.textContent = state.originalStream ? `Edit ${state.originalStream.name}` : "New stream";
    section.append(heading);

    previewButton.textContent = state.originalStream ? "Preview update" : "Preview create";
    previewButton.type = "submit";

    appendTextInput(form, "Name", state.streamForm.name, (value) => {
      state.streamForm.name = value;
      markPreviewStale();
    });
    appendTextInput(
      form,
      "Listen port",
      state.streamForm.listenPort,
      (value) => {
        state.streamForm.listenPort = value;
        markPreviewStale();
      },
      "number",
    );
    appendTextInput(form, "Upstream host", state.streamForm.upstreamHost, (value) => {
      state.streamForm.upstreamHost = value;
      markPreviewStale();
    });
    appendTextInput(
      form,
      "Upstream port",
      state.streamForm.upstreamPort,
      (value) => {
        state.streamForm.upstreamPort = value;
        markPreviewStale();
      },
      "number",
    );

    const cancelButton = document.createElement("button");
    cancelButton.textContent = state.originalStream ? "Cancel edit" : "Reset form";
    cancelButton.type = "button";
    cancelButton.addEventListener("click", () => {
      resetStreamEditor();
      safeRender();
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void previewCurrentStreamForm();
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
      serverCell.append(renderDomainLink(service.server_name, service.server_name));
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

  function renderStreamList(): HTMLElement {
    const heading = document.createElement("h3");
    const section = document.createElement("div");

    heading.textContent = "Streams";
    section.append(heading);

    if (state.loadingStreams) {
      const loading = document.createElement("p");
      loading.textContent = "Loading streams…";
      section.append(loading);
      return section;
    }

    if (state.streams.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No streams found.";
      section.append(empty);
      return section;
    }

    const table = document.createElement("table");
    const headerRow = document.createElement("tr");

    styleTable(table);
    for (const title of ["Name", "Listen port", "Upstream", "Actions"]) {
      const cell = document.createElement("th");
      cell.textContent = title;
      styleTableCell(cell, true);
      headerRow.append(cell);
    }
    table.append(headerRow);

    for (const stream of state.streams) {
      const actionsCell = document.createElement("td");
      const deleteButton = document.createElement("button");
      const editButton = document.createElement("button");
      const listenPortCell = document.createElement("td");
      const nameCell = document.createElement("td");
      const row = document.createElement("tr");
      const upstreamCell = document.createElement("td");

      // Raw TCP passthrough has no HTTP endpoint to link to (unlike a
      // service's server_name), so the upstream is shown as plain text.
      listenPortCell.textContent = String(stream.listen_port);
      nameCell.textContent = stream.name;
      upstreamCell.textContent = `${stream.upstream.host}:${stream.upstream.port}`;
      styleTableCell(actionsCell);
      styleTableCell(listenPortCell);
      styleTableCell(nameCell);
      styleTableCell(upstreamCell);

      editButton.textContent = "Edit";
      editButton.type = "button";
      editButton.addEventListener("click", () => {
        void beginEditStream(stream.name);
      });

      deleteButton.textContent = "Preview delete";
      deleteButton.type = "button";
      deleteButton.addEventListener("click", () => {
        void beginDeleteStream(stream.name);
      });

      actionsCell.append(editButton, document.createTextNode(" "), deleteButton);
      row.append(nameCell, listenPortCell, upstreamCell, actionsCell);
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

  function resetStreamEditor(): void {
    state.streamForm = blankStreamFormState();
    state.originalStream = null;
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
      domainCell.append(renderDomainLink(extractCertDomain(check), "Unavailable from current API response"));
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

function blankSmtpFormState(): SmtpSettingsFormState {
  return {
    fromAddress: "",
    host: "",
    mailDomain: "",
    password: "",
    port: "25",
    username: "",
  };
}

function smtpConfigToFormState(config: null | SmtpConfigOut): SmtpSettingsFormState {
  if (!config) {
    return blankSmtpFormState();
  }
  return {
    fromAddress: config.from_address,
    host: config.host,
    mailDomain: config.mail_domain,
    password: "",
    port: String(config.port),
    username: config.username,
  };
}

function mountSettingsPanel(root: HTMLElement): () => void {
  const state: SmtpSettingsState = {
    deleting: false,
    error: null,
    existing: null,
    form: blankSmtpFormState(),
    loading: true,
    message: null,
    saving: false,
    testPassed: false,
    testRecipient: "",
    testing: false,
  };
  let disposed = false;

  render();
  void refreshSettings();

  return () => {
    disposed = true;
    root.replaceChildren();
  };

  function buildDraft(): SmtpConfigIn {
    return {
      from_address: state.form.fromAddress.trim(),
      host: state.form.host.trim(),
      mail_domain: state.form.mailDomain.trim(),
      password: state.form.password === "" ? null : state.form.password,
      port: Number(state.form.port) || 25,
      username: state.form.username.trim(),
    };
  }

  function deleteSettings(): void {
    if (state.deleting || disposed) {
      return;
    }
    state.deleting = true;
    state.error = null;
    state.message = "Deleting SMTP settings…";
    safeRender();
    deleteSmtpSettings()
      .then(() => {
        if (disposed) {
          return;
        }
        state.existing = null;
        state.form = blankSmtpFormState();
        state.testPassed = false;
        state.message = "Deleted SMTP settings.";
      })
      .catch((error: unknown) => {
        if (disposed) {
          return;
        }
        state.error = error instanceof Error ? error.message : "Failed to delete SMTP settings";
      })
      .finally(() => {
        if (disposed) {
          return;
        }
        state.deleting = false;
        safeRender();
      });
  }

  function markDirty(): void {
    state.testPassed = false;
    safeRender();
  }

  async function refreshSettings(): Promise<void> {
    try {
      const existing = await readSmtpSettings();
      if (disposed) {
        return;
      }
      state.existing = existing;
      state.form = smtpConfigToFormState(existing);
      state.testPassed = existing !== null;
    } catch (error: unknown) {
      if (disposed) {
        return;
      }
      state.error = error instanceof Error ? error.message : "Failed to load SMTP settings";
    } finally {
      if (!disposed) {
        state.loading = false;
        safeRender();
      }
    }
  }

  function render(): void {
    const card = document.createElement("div");
    const heading = document.createElement("h2");
    const lead = document.createElement("p");
    const form = document.createElement("form");

    heading.textContent = "SMTP settings";
    lead.classList.add("message");
    lead.textContent = "Outgoing email for catalog-health alerts. Send a successful test before saving.";
    form.noValidate = true;

    appendTextInput(form, "SMTP host", state.form.host, (value) => {
      state.form.host = value;
      markDirty();
    });
    appendTextInput(
      form,
      "Port",
      state.form.port,
      (value) => {
        state.form.port = value;
        markDirty();
      },
      "number",
    );
    appendTextInput(form, "Username (optional)", state.form.username, (value) => {
      state.form.username = value;
      markDirty();
    });
    appendTextInput(
      form,
      state.existing?.password_configured ? "Password (leave blank to keep current)" : "Password (optional)",
      state.form.password,
      (value) => {
        state.form.password = value;
        markDirty();
      },
      "password",
    );
    appendTextInput(form, "Mail domain", state.form.mailDomain, (value) => {
      state.form.mailDomain = value;
      markDirty();
    });
    appendTextInput(form, "From address", state.form.fromAddress, (value) => {
      state.form.fromAddress = value;
      markDirty();
    });

    const actions = document.createElement("div");
    const saveButton = document.createElement("button");
    const deleteButton = document.createElement("button");

    saveButton.disabled = !state.testPassed || state.saving || state.loading;
    saveButton.title = state.testPassed ? "" : "Send a successful test email first";
    saveButton.textContent = state.saving ? "Saving…" : "Save SMTP settings";
    saveButton.type = "button";
    saveButton.addEventListener("click", saveSettings);

    deleteButton.disabled = state.existing === null || state.deleting || state.loading;
    deleteButton.textContent = state.deleting ? "Deleting…" : "Delete SMTP settings";
    deleteButton.type = "button";
    deleteButton.addEventListener("click", deleteSettings);

    actions.append(saveButton, deleteButton);
    form.append(actions);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      saveSettings();
    });

    const testHeading = document.createElement("h3");
    testHeading.textContent = "Send test email";

    const testForm = document.createElement("form");
    testForm.noValidate = true;
    appendTextInput(
      testForm,
      "Recipient",
      state.testRecipient,
      (value) => {
        state.testRecipient = value;
      },
      "email",
    );
    const testButton = document.createElement("button");
    testButton.disabled = state.testing || state.loading;
    testButton.textContent = state.testing ? "Sending…" : "Send test email";
    testButton.type = "button";
    testButton.addEventListener("click", sendTestEmail);
    testForm.append(testButton);
    testForm.addEventListener("submit", (event) => {
      event.preventDefault();
      sendTestEmail();
    });

    card.append(heading, lead);
    if (state.loading) {
      const loadingNode = document.createElement("p");
      loadingNode.classList.add("message");
      loadingNode.textContent = "Loading…";
      card.append(loadingNode);
    }
    card.append(form, testHeading, testForm);

    if (state.message) {
      const messageNode = document.createElement("p");
      messageNode.classList.add("message");
      messageNode.textContent = state.message;
      card.append(messageNode);
    }
    if (state.error) {
      const errorNode = document.createElement("p");
      errorNode.classList.add("error-banner");
      errorNode.textContent = state.error;
      card.append(errorNode);
    }

    styleSection(card);
    root.replaceChildren(card);
  }

  function safeRender(): void {
    if (!disposed) {
      render();
    }
  }

  function saveSettings(): void {
    if (!state.testPassed || state.saving || disposed) {
      return;
    }
    state.saving = true;
    state.error = null;
    state.message = "Saving SMTP settings…";
    safeRender();
    saveSmtpSettings(buildDraft())
      .then((saved) => {
        if (disposed) {
          return;
        }
        state.existing = saved;
        state.form = smtpConfigToFormState(saved);
        state.message = `Saved SMTP settings for ${saved.host}:${saved.port}.`;
      })
      .catch((error: unknown) => {
        if (disposed) {
          return;
        }
        state.error = error instanceof Error ? error.message : "Failed to save SMTP settings";
      })
      .finally(() => {
        if (disposed) {
          return;
        }
        state.saving = false;
        safeRender();
      });
  }

  function sendTestEmail(): void {
    if (state.testing || disposed) {
      return;
    }
    if (state.form.host.trim() === "") {
      state.error = "Expected SMTP host, got empty value";
      safeRender();
      return;
    }
    if (state.form.mailDomain.trim() === "") {
      state.error = "Expected mail domain, got empty value";
      safeRender();
      return;
    }
    if (state.testRecipient.trim() === "") {
      state.error = "Expected recipient email, got empty value";
      safeRender();
      return;
    }
    state.testing = true;
    state.error = null;
    state.message = "Sending test email…";
    safeRender();
    sendSmtpTestEmail({ ...buildDraft(), to_address: state.testRecipient.trim() })
      .then((result) => {
        if (disposed) {
          return;
        }
        if (result.ok) {
          state.testPassed = true;
          state.message = result.message;
        } else {
          state.error = result.message;
          state.message = null;
        }
      })
      .catch((error: unknown) => {
        if (disposed) {
          return;
        }
        state.error = error instanceof Error ? error.message : "Failed to send test email";
      })
      .finally(() => {
        if (disposed) {
          return;
        }
        state.testing = false;
        safeRender();
      });
  }
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

async function readCatalogStream(name: string): Promise<StreamEntry> {
  const response = await fetchJson<{ stream: StreamEntry }>(`/catalog/streams/${encodeURIComponent(name)}`, {
    method: "GET",
  });
  return response.stream;
}

async function readCatalogStreams(): Promise<StreamEntry[]> {
  const response = await fetchJson<{ streams: StreamEntry[] }>("/catalog/streams", {
    method: "GET",
  });
  return response.streams;
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

async function readSmtpSettings(): Promise<null | SmtpConfigOut> {
  return fetchJson<null | SmtpConfigOut>("/settings/smtp", { method: "GET" });
}

async function saveSmtpSettings(payload: SmtpConfigIn): Promise<SmtpConfigOut> {
  return fetchJson<SmtpConfigOut>("/settings/smtp", {
    body: JSON.stringify(payload),
    headers: { "Content-Type": "application/json" },
    method: "PUT",
  });
}

async function deleteSmtpSettings(): Promise<void> {
  const response = await fetch("/settings/smtp", {
    credentials: "same-origin",
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error(await errorMessage(response));
  }
}

async function sendSmtpTestEmail(payload: SmtpTestEmailIn): Promise<SmtpTestEmailOut> {
  return fetchJson<SmtpTestEmailOut>("/settings/smtp/test", {
    body: JSON.stringify(payload),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
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
  const settingsButton = document.createElement("button");
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

  settingsButton.textContent = "Settings";
  settingsButton.type = "button";
  settingsButton.addEventListener("click", () => {
    mountView("settings");
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
  menuPanel.append(healthButton, catalogButton, settingsButton, aboutButton);

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
    settingsButton.disabled = activeView === "settings";
    unmountCurrentView =
      activeView === "catalog"
        ? mountCatalogManager(shell)
        : activeView === "about"
          ? mountAboutPanel(shell, username)
          : activeView === "settings"
            ? mountSettingsPanel(shell)
            : mountHealthDashboard(shell);
  }
}


function serviceToFormState(service: ServiceEntry): FormState {
  return {
    allowCidrs: (service.allow_cidrs ?? []).join("\n"),
    forwardClientIp: service.forward_client_ip === true,
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
