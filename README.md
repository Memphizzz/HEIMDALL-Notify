# HEIMDALL-Notify

Notification stack for HEIMDALL with built-in Threema Gateway support.

Single container running Gotify + Threema Bridge. Each HEIMDALL user deploys their own instance.

## Architecture

```
HEIMDALL Cloud (SaaS)
      |
      | HTTPS POST (alert)
      v
   HEIMDALL-Notify Container
   +---------------------------+
   |  Gotify (:80)             |
   |      |                    |
   |      | WebSocket          |
   |      v                    |
   |  Threema Bridge           |
   +---------------------------+
      |
      | E2E Encrypted
      v
 Threema Gateway API → Your Phone
```

## Deploy on Railway

1. Fork this repo to your GitHub account
2. Create a new Railway project
3. Add service → GitHub Repo → Select your fork
4. Set environment variables (see below)
5. **Add a volume**: Settings → Volumes → Add Volume → Mount path: `/app/data`
6. In Settings → Networking, expose port `8080`
7. Deploy

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GOTIFY_DEFAULTUSER_NAME` | Gotify admin username (default: `admin`) |
| `GOTIFY_DEFAULTUSER_PASS` | Gotify admin password |
| `THREEMA_GATEWAY_ID` | Your gateway ID (format: `*XXXXXXX`) |
| `THREEMA_API_SECRET` | Gateway API secret |
| `THREEMA_PRIVATE_KEY` | 64-char hex private key for E2E encryption |
| `THREEMA_RECIPIENT_ID` | 8-char Threema ID to receive alerts |

### Get the App Token

Check the **logs** in Railway on **first deploy**. The token is shown once:
```
============================================================
GOTIFY CONFIGURATION - SAVE THIS TOKEN!
============================================================
Use this token in HEIMDALL notification settings:
HEIMDALL_GOTIFY_APP_TOKEN=xxxxxxxxxxxxxx

This token is only shown once. It persists across restarts
as long as the data volume is preserved.
============================================================
```

**Important:** The token persists in the volume. Subsequent restarts won't show it again.

### Configure HEIMDALL

In your HEIMDALL notification settings:
- **Gotify URL**: Your public Railway URL (e.g., `https://heimdall-notify-xxxx.up.railway.app`)
- **App Token**: The token from the logs

## Security

- Gotify requires an **app token** to send messages
- Threema credentials stay in your deployment
- All traffic over HTTPS

## Local Development

```bash
cp .env.example .env
# Edit .env with your values
docker compose up -d
docker compose logs -f
```

## Extensibility

Gotify is the hub - you can add more notification channels:
- Gotify mobile app
- Telegram bots
- Discord/Slack webhooks
- Custom integrations

HEIMDALL sends to Gotify, you choose how to receive alerts.
