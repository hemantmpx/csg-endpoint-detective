# Deployment

Local classroom setup uses Docker Compose, PostgreSQL 16, FastAPI, Next.js, and Caddy. Copy `.env.example` to `.env`, set classroom secrets, then run `docker compose up --build -d`. The local reverse proxy serves HTTP on port 8080 by default; set `HTTP_PORT` in `.env` to change the host mapping.

For an internet-facing classroom, point a DNS name at the host, set `PUBLIC_HOST` to that name, `HTTP_PORT=80`, and `COOKIE_SECURE=true` in `.env`, then run `docker compose -f docker-compose.yml -f docker-compose.public.yml up --build -d`. The public override publishes port 443, and Caddy obtains and renews the hostname's TLS certificate.

## Temporary classroom link

When a permanent domain and hosted server are not ready, Cloudflare Quick Tunnels can provide a temporary HTTPS URL to the running classroom. They are intended for development and testing: the URL changes when the tunnel stops, and anyone who has the URL can reach the app. Keep the class code enabled and share the URL and code only with the class. Replace the `CHANGE-ME-UNIQUE-CODE` placeholder in `.env` with a unique class code before exposing a fresh deployment.

With Docker Compose v2.24 or newer, start the tunnel from the repository root:

```sh
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d cloudflared
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml logs -f cloudflared
```

Copy the `https://….trycloudflare.com` URL printed in the tunnel logs and open it in a private browser window to confirm the student sign-in page loads. The tunnel is attached to Caddy over the private Compose network; the local app port remains bound to loopback. Stop the tunnel after class with `docker compose -f docker-compose.yml -f docker-compose.tunnel.yml stop cloudflared`. Run `docker compose -f docker-compose.yml -f docker-compose.tunnel.yml down` when the whole classroom stack can be stopped. Starting a new Quick Tunnel creates a new URL.

For a stable classroom URL, deploy the app on an always-on host and use a domain with the production instructions above, or configure a named Cloudflare Tunnel with a hostname. Quick Tunnels do not provide a reserved hostname or uptime guarantee.

PostgreSQL is internal to the Compose network and uses a persistent named volume. Back up the `classroom-db` volume or export CSV before a full reset. The student UI uses same-origin `/api` requests through Caddy. No live Wazuh, research services, or endpoint machine is contacted.
