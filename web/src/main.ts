// Entry point for home-warden's admin web UI (the-hcma/home-warden#55).
//
// Scaffold-only (the-hcma/home-warden#67): this proves the pnpm + esbuild +
// TypeScript pipeline end-to-end -- static text, no fetches, no real
// features yet. Later sub-issues (#69 catalog CRUD, #70 health dashboard)
// replace this with real panels.

function mount(root: HTMLElement): void {
  const heading = document.createElement("h1");
  heading.textContent = "home-warden";

  const status = document.createElement("p");
  status.textContent = "Web UI scaffold is running.";

  root.append(heading, status);
}

const root = document.getElementById("app");
if (root) {
  mount(root);
} else {
  // Fails loudly in the browser console rather than silently doing nothing --
  // a missing #app means index.html and main.ts have drifted apart.
  console.error("home-warden: #app root element not found");
}
