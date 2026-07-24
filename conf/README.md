# Local configuration (not committed)

Copy the `*.example` files without the `.example` suffix and fill in real values
**in the primary clone** (`git worktree list` → first path):

| Example | Runtime path (gitignored) |
| --- | --- |
| `certbot-domains.example` | `conf/certbot-domains` |
| `cloudflare.ini.example` | `conf/cloudflare.ini` |

`scripts/cert-renewer` reads these paths by default (override with env if needed).

## Git worktrees

Linked worktrees should not keep a second copy of these files. Run:

```bash
./scripts/link-runtime-conf
```

That symlinks `conf/cloudflare.ini` and `conf/certbot-domains` from the primary
clone. `cert-renewer` invokes the same helper automatically before reading conf/.
