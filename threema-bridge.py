#!/usr/bin/env python3
"""
Gotify -> Threema Gateway Bridge (E2E Mode)
Listens to Gotify websocket and forwards encrypted messages to Threema.

On startup, auto-provisions Gotify client (for receiving) and application (for HEIMDALL to send).
"""

import os
import sys
import json
import time
import requests
import websocket
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random

# Configuration from environment
GOTIFY_URL = os.environ.get("GOTIFY_URL", "http://localhost:80")
GOTIFY_ADMIN_USER = os.environ.get("GOTIFY_ADMIN_USER", "admin")
GOTIFY_ADMIN_PASS = os.environ.get("GOTIFY_ADMIN_PASS")

THREEMA_GATEWAY_ID = os.environ.get("THREEMA_GATEWAY_ID")  # Your *XXXXXXX ID
THREEMA_API_SECRET = os.environ.get("THREEMA_API_SECRET")
THREEMA_PRIVATE_KEY = os.environ.get("THREEMA_PRIVATE_KEY")  # 64 hex chars
THREEMA_RECIPIENT_ID = os.environ.get("THREEMA_RECIPIENT_ID")  # Recipient's Threema ID

THREEMA_API_BASE = "https://msgapi.threema.ch"

# Cache for recipient public key
_recipient_pubkey_cache = {}

# Will be set during bootstrap
_gotify_client_token = None

# Whether Threema is configured
_threema_enabled = False


def validate_config() -> bool:
    """
    Check required env vars. Returns True if Threema is configured.
    Gotify admin pass is always required, Threema vars are optional.
    """
    global _threema_enabled

    if not GOTIFY_ADMIN_PASS:
        print("ERROR: GOTIFY_ADMIN_PASS is required")
        sys.exit(1)

    # Check if Threema is configured (all vars must be set)
    threema_vars = [THREEMA_GATEWAY_ID, THREEMA_API_SECRET, THREEMA_PRIVATE_KEY, THREEMA_RECIPIENT_ID]
    if all(threema_vars):
        _threema_enabled = True

        # Validate formats
        if not THREEMA_GATEWAY_ID.startswith("*"):
            print(f"WARNING: THREEMA_GATEWAY_ID should start with '*' (got: {THREEMA_GATEWAY_ID})")

        if len(THREEMA_GATEWAY_ID) != 8:
            print(f"WARNING: THREEMA_GATEWAY_ID should be 8 characters (got: {len(THREEMA_GATEWAY_ID)})")

        if len(THREEMA_PRIVATE_KEY) != 64:
            print(f"ERROR: THREEMA_PRIVATE_KEY should be 64 hex characters (got: {len(THREEMA_PRIVATE_KEY)})")
            sys.exit(1)

        if len(THREEMA_RECIPIENT_ID) != 8:
            print(f"WARNING: THREEMA_RECIPIENT_ID should be 8 characters (got: {len(THREEMA_RECIPIENT_ID)})")
    elif any(threema_vars):
        # Partial config - warn user
        print("WARNING: Threema partially configured - set all THREEMA_* vars to enable")
        _threema_enabled = False
    else:
        print("Threema not configured - Gotify-only mode")
        _threema_enabled = False

    return _threema_enabled


def wait_for_gotify(max_retries: int = 30, retry_delay: int = 2) -> bool:
    """Wait for Gotify to be ready"""
    print(f"Waiting for Gotify at {GOTIFY_URL}...")
    for i in range(max_retries):
        try:
            response = requests.get(f"{GOTIFY_URL}/health", timeout=5)
            if response.status_code == 200:
                print("Gotify is ready")
                return True
        except requests.exceptions.RequestException:
            pass
        print(f"  Retry {i + 1}/{max_retries}...")
        time.sleep(retry_delay)
    return False


def bootstrap_gotify() -> str:
    """
    Auto-provision Gotify client and application.
    Returns the client token for WebSocket connection.
    """
    global _gotify_client_token
    auth = (GOTIFY_ADMIN_USER, GOTIFY_ADMIN_PASS)

    # Check for existing HEIMDALL application
    print("Checking for existing Gotify configuration...")

    # Get existing applications
    response = requests.get(f"{GOTIFY_URL}/application", auth=auth, timeout=10)
    if response.status_code != 200:
        print(f"ERROR: Failed to list applications: {response.status_code}")
        sys.exit(1)

    apps = response.json()
    heimdall_app = next((a for a in apps if a.get("name") == "HEIMDALL"), None)

    if heimdall_app:
        # App exists - don't recreate, token is still valid even if we can't see it
        print("Found existing HEIMDALL application (token unchanged)")
        app_token = None  # We don't need it, just log for first-time setup
    else:
        # Create application for HEIMDALL to send alerts
        print("Creating HEIMDALL application...")
        response = requests.post(
            f"{GOTIFY_URL}/application",
            auth=auth,
            json={"name": "HEIMDALL", "description": "HEIMDALL monitoring alerts"},
            timeout=10
        )
        if response.status_code != 200:
            print(f"ERROR: Failed to create application: {response.status_code} {response.text}")
            sys.exit(1)
        app_token = response.json().get("token")
        print("Created HEIMDALL application")

    # Get existing clients
    response = requests.get(f"{GOTIFY_URL}/client", auth=auth, timeout=10)
    if response.status_code != 200:
        print(f"ERROR: Failed to list clients: {response.status_code}")
        sys.exit(1)

    clients = response.json()
    bridge_client = next((c for c in clients if c.get("name") == "Threema-Bridge"), None)

    if bridge_client:
        client_token = bridge_client.get("token")
        if client_token:
            print(f"Found existing Threema-Bridge client")
        else:
            # Token not returned in list, delete and recreate
            print("Recreating Threema-Bridge client (token not available)...")
            client_id = bridge_client.get("id")
            requests.delete(f"{GOTIFY_URL}/client/{client_id}", auth=auth, timeout=10)
            response = requests.post(
                f"{GOTIFY_URL}/client",
                auth=auth,
                json={"name": "Threema-Bridge"},
                timeout=10
            )
            if response.status_code != 200:
                print(f"ERROR: Failed to create client: {response.status_code} {response.text}")
                sys.exit(1)
            client_token = response.json().get("token")
            print("Recreated Threema-Bridge client")
    else:
        # Create client for this bridge to receive messages
        print("Creating Threema-Bridge client...")
        response = requests.post(
            f"{GOTIFY_URL}/client",
            auth=auth,
            json={"name": "Threema-Bridge"},
            timeout=10
        )
        if response.status_code != 200:
            print(f"ERROR: Failed to create client: {response.status_code} {response.text}")
            sys.exit(1)
        client_token = response.json().get("token")
        print("Created Threema-Bridge client")

    # Log the app token prominently for HEIMDALL configuration (only on first run)
    if app_token:
        print()
        print("=" * 60)
        print("GOTIFY CONFIGURATION - SAVE THIS TOKEN!")
        print("=" * 60)
        print()
        print("Use this token in HEIMDALL notification settings:")
        print(f"HEIMDALL_GOTIFY_APP_TOKEN={app_token}")
        print()
        print("This token is only shown once. It persists across restarts")
        print("as long as the data volume is preserved.")
        print("=" * 60)
        print()

    _gotify_client_token = client_token
    return client_token


def get_recipient_pubkey(recipient_id: str) -> bytes:
    """Fetch and cache recipient's public key from Threema API"""
    if recipient_id in _recipient_pubkey_cache:
        return _recipient_pubkey_cache[recipient_id]

    url = f"{THREEMA_API_BASE}/pubkeys/{recipient_id}"
    params = {"from": THREEMA_GATEWAY_ID, "secret": THREEMA_API_SECRET}

    response = requests.get(url, params=params, timeout=10)

    if response.status_code == 200:
        pubkey_hex = response.text.strip()
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        _recipient_pubkey_cache[recipient_id] = pubkey_bytes
        print(f"Fetched public key for {recipient_id}")
        return pubkey_bytes
    elif response.status_code == 404:
        raise ValueError(f"Recipient {recipient_id} not found")
    else:
        raise ValueError(f"Failed to fetch public key: {response.status_code} {response.text}")


def encrypt_text_message(text: str, recipient_pubkey: bytes, private_key_hex: str) -> tuple:
    """
    Encrypt a text message for Threema E2E API
    Returns (nonce_hex, box_hex)
    """
    # Decode keys
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = PrivateKey(private_key_bytes)
    public_key = PublicKey(recipient_pubkey)

    # Create encryption box
    box = Box(private_key, public_key)

    # Threema text message format:
    # 1 byte type (0x01 for text) + UTF-8 text + padding
    text_bytes = text.encode('utf-8')

    # Message type 0x01 = text
    message = bytes([0x01]) + text_bytes

    # Add PKCS#7 padding to multiple of 256 (Threema requirement)
    padded_len = ((len(message) + 255) // 256) * 256
    if padded_len < 32:
        padded_len = 32  # Minimum 32 bytes
    padding_len = padded_len - len(message)
    message = message + bytes([padding_len] * padding_len)

    # Generate random nonce (24 bytes)
    nonce = random(24)

    # Encrypt
    encrypted = box.encrypt(message, nonce)
    # box.encrypt returns nonce + ciphertext, we just need ciphertext
    ciphertext = encrypted.ciphertext

    return nonce.hex(), ciphertext.hex()


def send_threema(title: str, message: str, priority: int = 0):
    """Send encrypted message via Threema Gateway E2E API"""

    # Format: title + message, no modifications
    text = f"{title}\n\n{message}" if message else title

    # Threema has a 3500 byte limit
    if len(text.encode('utf-8')) > 3500:
        text = text[:3400] + "...[truncated]"

    recipient = THREEMA_RECIPIENT_ID.upper()

    try:
        # Get recipient's public key
        recipient_pubkey = get_recipient_pubkey(recipient)

        # Encrypt the message
        nonce_hex, box_hex = encrypt_text_message(text, recipient_pubkey, THREEMA_PRIVATE_KEY)

        # Send via E2E API
        url = f"{THREEMA_API_BASE}/send_e2e"
        payload = {
            "from": THREEMA_GATEWAY_ID,
            "to": recipient,
            "nonce": nonce_hex,
            "box": box_hex,
            "secret": THREEMA_API_SECRET,
        }

        response = requests.post(
            url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10
        )

        if response.status_code == 200:
            msg_id = response.text.strip()
            print(f"Sent encrypted message (id: {msg_id}): {title[:50]}...")
        elif response.status_code == 400:
            print(f"Threema API error 400: Bad request")
            print(f"  Response: {response.text}")
        elif response.status_code == 401:
            print(f"Threema API error 401: Invalid API identity or secret")
        elif response.status_code == 402:
            print(f"Threema API error 402: No credits remaining!")
        else:
            print(f"Threema API error {response.status_code}: {response.text}")

    except Exception as e:
        print(f"Failed to send to Threema: {e}")


def on_message(ws, message):
    """Handle incoming Gotify message"""
    try:
        data = json.loads(message)
        title = data.get("title", "Notification")
        msg = data.get("message", "")
        priority = data.get("priority", 0)

        print(f"Gotify: [{priority}] {title}")
        if _threema_enabled:
            send_threema(title, msg, priority)

    except json.JSONDecodeError:
        print(f"Failed to parse message: {message}")


def on_error(ws, error):
    print(f"WebSocket error: {error}")


def on_close(ws, close_status_code, close_msg):
    print(f"WebSocket closed: {close_status_code} - {close_msg}")


def on_open(ws):
    print(f"Connected to Gotify websocket")


def main():
    print("HEIMDALL-Notify")
    print()

    threema_enabled = validate_config()

    # Wait for Gotify to be available
    if not wait_for_gotify():
        print("ERROR: Gotify not available after max retries")
        sys.exit(1)

    # Bootstrap: create client and application
    client_token = bootstrap_gotify()

    # Build websocket URL
    ws_url = GOTIFY_URL.replace("http://", "ws://").replace("https://", "wss://")
    ws_url = f"{ws_url}/stream?token={client_token}"

    if threema_enabled:
        print(f"Threema Gateway ID: {THREEMA_GATEWAY_ID}")
        print(f"Threema Recipient: {THREEMA_RECIPIENT_ID}")
        print()

        # Test: fetch recipient public key on startup
        try:
            get_recipient_pubkey(THREEMA_RECIPIENT_ID.upper())
        except Exception as e:
            print(f"ERROR: Could not fetch recipient public key: {e}")
            sys.exit(1)
    else:
        print("Running in Gotify-only mode (no Threema forwarding)")
        print()

    while True:
        try:
            print(f"Connecting to Gotify websocket...")
            ws = websocket.WebSocketApp(
                ws_url,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )
            ws.run_forever()

        except Exception as e:
            print(f"Connection failed: {e}")

        print("Reconnecting in 5 seconds...")
        time.sleep(5)


if __name__ == "__main__":
    main()
