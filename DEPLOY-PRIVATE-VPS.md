# Deploy the scanner privately on a Tailscale VPS

This deploys the FastAPI scanner, Celery worker, PostgreSQL, Redis, ClamAV, and YARA on a private VPS. GitHub Pages remains a static frontend. The API is served only inside your tailnet through Tailscale Serve.

## 1. Prepare the VPS

Use an Ubuntu 22.04 VPS with Docker Engine, the Docker Compose plugin, and Tailscale installed and authenticated to your tailnet. Keep inbound public firewall access closed for ports `8000`, `5432`, `6379`, and `3310`.

In the VPS console:

```bash
sudo git clone https://github.com/funnythirat/deea.git /opt/deea
cd /opt/deea
```

Create a private database password file. Do not commit or share `.env`:

```bash
sudo sh -c 'umask 077; printf "POSTGRES_PASSWORD=%s\n" "$(openssl rand -hex 32)" > /opt/deea/.env'
```

Start the stack and verify it locally:

```bash
cd /opt/deea
sudo docker compose -f docker-compose.yml -f docker-compose.production.yml config --quiet
sudo docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
sudo docker compose ps
curl --fail http://127.0.0.1:8000/api/v1/health
```

The API must report `status: ready` and all of `database`, `redis`, `worker`, `clamav`, and `yara` as `true`.

Before deploying a version that adds scan ownership, apply the additive database migration from the repository. On an existing deployment, run it before recreating the API container:

```bash
cd /opt/deea
docker compose -f docker-compose.yml -f docker-compose.production.yml exec -T db \
  psql -U scanner -d scanner < backend/migrations/0001_add_scan_ownership.sql
```

The migration preserves existing scan rows. Older rows remain capability-token-only; newly created scans are tied to the authenticated Firebase UID.

## 2. Serve HTTPS inside Tailscale only

Keep the Compose API port bound to `127.0.0.1`. On the VPS, enable Tailscale Serve (not Funnel):

```bash
sudo tailscale serve --bg 8000
sudo tailscale serve status
```

Use the HTTPS MagicDNS URL shown by `tailscale serve status`. Do not enable Tailscale Funnel and do not expose the API port through a public reverse proxy or firewall. A MagicDNS URL should have the full form `https://machine-name.tailnet-name.ts.net`; the API is expected to be reachable only from a device signed in to the same tailnet.

From a device connected to the same tailnet, verify:

```text
https://<full-machine-name>.<tailnet-name>.ts.net/api/v1/health
```

The address must return the same healthy JSON. A short or incomplete `*.ts.net` name that does not resolve cannot be used; copy the full HTTPS URL shown by Tailscale.

## 3. Connect GitHub Pages to the private API

In the repository's `index.html`, set the `scanner-api-base` meta tag to the exact HTTPS origin from Tailscale Serve, with no trailing path. The Pages source currently uses `https://desktop-hubjhjb.tailc7972e.ts.net`; replace it if `tailscale serve status` on the backend machine shows another name:

```html
<meta name="scanner-api-base" content="https://scanner.example-tailnet.ts.net">
```

Commit and push that frontend change. The API CORS allowlist defaults to the exact GitHub Pages origin `https://funnythirat.github.io`; configure `CORS_ORIGINS` in `.env` only if the frontend has an additional known origin.

All devices using the scanner API must be signed in to the same tailnet. GitHub Pages itself is public, but the API host remains private. CORS is browser policy, not authentication; tailnet access remains an additional network boundary. File uploads, scan-result reads for new scans, website-header checks, and Wi-Fi reports require a valid Firebase ID token; scan results are scoped to the creating UID. Redis-backed per-user rate limits protect these API operations. Historical scans created before the ownership migration remain accessible only with their original capability token. This does not constitute a complete public deployment review: do not enable Funnel or expose the API publicly until email verification, quotas/retention, monitoring, backups, and an external security review are addressed.

## 4. Updates and operations

For an update, back up the database first, then run:

```bash
cd /opt/deea
sudo git pull --ff-only
sudo docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
sudo docker compose ps
curl --fail http://127.0.0.1:8000/api/v1/health
```

Use `sudo docker compose ... down` to stop services while preserving data. Do not use `down -v` unless you intentionally want to delete the PostgreSQL database, ClamAV signatures, and quarantine volume.
