import unittest
from unittest.mock import patch, MagicMock

from alerts.discord_notifier import build_payload, send_alert


class DiscordNotifierTests(unittest.TestCase):
    def test_payload_blocked(self):
        p = build_payload("blocked", "SQL Injection", "Параметризація")
        self.assertEqual(p["embeds"][0]["title"], "Ланцюг атаки заблоковано")

    def test_payload_bypass(self):
        p = build_payload("bypass", "XSS", "Валідація", "payload пройшов")
        self.assertEqual(p["embeds"][0]["color"], 0xE74C3C)

    def test_invalid_event(self):
        with self.assertRaises(ValueError):
            build_payload("oops", "XSS", "x")

    def test_no_url_returns_false(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(send_alert("blocked", "XSS", "x"))

    @patch("alerts.discord_notifier.urllib.request.urlopen")
    def test_send_ok(self, urlopen):
        resp = MagicMock(status=204)
        urlopen.return_value.__enter__.return_value = resp
        self.assertTrue(send_alert("blocked", "XSS", "x", webhook_url="https://example.test/hook"))

    @patch("alerts.discord_notifier.urllib.request.urlopen", side_effect=OSError)
    def test_send_network_error(self, _):
        self.assertFalse(send_alert("bypass", "XSS", "x", webhook_url="https://example.test/hook"))


if __name__ == "__main__":
    unittest.main()