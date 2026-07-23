# Local configuration (not committed)

Copy the `*.example` files without the `.example` suffix and fill in real values:

| Example | Runtime path (gitignored) |
| --- | --- |
| `certbot-domains.example` | `conf/certbot-domains` |
| `cloudflare.ini.example` | `conf/cloudflare.ini` |

`scripts/cert-renewer` reads these paths by default (override with env if needed).
