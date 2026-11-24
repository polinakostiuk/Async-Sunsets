"""Сповіщення SecureFlow у Discord через Webhook (stdlib, без залежностей)."""
import json
import os
import urllib.request

COLORS = {"blocked": 0x2ECC71, "bypass": 0xE74C3C}


def build_payload(event: str, attack: str, step: str, details: str = "") -> dict:
    """Формує JSON для Discord. event: 'blocked' (ланцюг розірвано) або 'bypass' (спроба обходу)."""
    if event not in COLORS:
        raise ValueError(f"Невідома подія: {event}")
    title = "Ланцюг атаки заблоковано" if event == "blocked" else "Критична спроба обходу захисту"
    return {
        "username": "SecureFlowAlertBot",
        "embeds": [{
            "title": title,
            "color": COLORS[event],
            "fields": [
                {"name": "Атака", "value": attack, "inline": True},
                {"name": "Етап", "value": step, "inline": True},
                {"name": "Деталі", "value": details or "—"},
            ],
        }],
    }


def send_alert(event: str, attack: str, step: str, details: str = "", webhook_url: str = None) -> bool:
    """Надсилає сповіщення. Повертає True при успіху; помилки не ламають симуляцію."""
    url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL")
    if not url:
        return False
    data = json.dumps(build_payload(event, attack, step, details)).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except OSError:
        return False