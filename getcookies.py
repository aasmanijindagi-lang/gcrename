#!/usr/bin/env python3
"""
instagrapi -> playwright converter
Saves:
  - <username>_session.json   (instagrapi dump/settings)
  - <username>_state.json     (playwright-compatible storage_state)

Usage:
  python instagrapi_playwright_save.py
Requires:
  pip install instagrapi
"""

import json
import time
import urllib.parse
from pathlib import Path
from getpass import getpass

from instagrapi import Client
from instagrapi.exceptions import TwoFactorRequired, ChallengeRequired, BadPassword, ClientError

# ---------------- helpers ----------------
def future_expiry(years=10):
    return int(time.time()) + years * 365 * 24 * 3600

def save_json(path: str, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# ---------------- convert ----------------
def convert_for_playwright(insta_data: dict):
    """
    Accepts parsed instagrapi settings/dump dict and returns playwright_state dict
    """
    cookies = []

    # 1) common 'authorization_data' map (name->value)
    auth = insta_data.get("authorization_data") or insta_data.get("authorization") or {}
    if isinstance(auth, dict) and auth:
        for name, value in auth.items():
            if value is None:
                continue
            cookies.append({
                "name": str(name),
                "value": urllib.parse.unquote(str(value)),
                "domain": ".instagram.com",
                "path": "/",
                "expires": future_expiry(),
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax"
            })

    # 2) look for cookie lists/dicts in known keys
    if not cookies:
        for key in ("cookies", "saved_cookies", "session_cookies", "cookie"):
            maybe = insta_data.get(key)
            if not maybe:
                continue
            # dict of name->value
            if isinstance(maybe, dict):
                for name, value in maybe.items():
                    cookies.append({
                        "name": str(name),
                        "value": urllib.parse.unquote(str(value)),
                        "domain": ".instagram.com",
                        "path": "/",
                        "expires": future_expiry(),
                        "httpOnly": True,
                        "secure": True,
                        "sameSite": "Lax"
                    })
            # list of cookie objects
            elif isinstance(maybe, list):
                for c in maybe:
                    try:
                        name = c.get("name") or c.get("key")
                        value = c.get("value") or c.get("val") or c.get("cookie")
                        domain = c.get("domain", ".instagram.com")
                        path = c.get("path", "/")
                        expires = int(c.get("expires", future_expiry()))
                        httpOnly = bool(c.get("httpOnly", True))
                        secure = bool(c.get("secure", True))
                        sameSite = c.get("sameSite", "Lax")
                        if name and value is not None:
                            cookies.append({
                                "name": str(name),
                                "value": urllib.parse.unquote(str(value)),
                                "domain": domain,
                                "path": path,
                                "expires": expires,
                                "httpOnly": httpOnly,
                                "secure": secure,
                                "sameSite": sameSite
                            })
                    except Exception:
                        continue

    # 3) fallback to nested settings/session -> cookies
    if not cookies:
        maybe = insta_data.get("settings") or insta_data.get("session") or {}
        if isinstance(maybe, dict):
            maybe_cookies = maybe.get("cookies")
            if isinstance(maybe_cookies, dict):
                for name, value in maybe_cookies.items():
                    cookies.append({
                        "name": str(name),
                        "value": urllib.parse.unquote(str(value)),
                        "domain": ".instagram.com",
                        "path": "/",
                        "expires": future_expiry(),
                        "httpOnly": True,
                        "secure": True,
                        "sameSite": "Lax"
                    })

    if not cookies:
        # nothing found
        return None

    return {
        "cookies": cookies,
        "origins": [
            {
                "origin": "https://www.instagram.com",
                "localStorage": []
            }
        ]
    }

# ---------------- main flow ----------------
def main():
    print("Instagrapi -> Playwright saver\n")
    username = input("Username: ").strip()
    if not username:
        print("[!] Username required. Exiting.")
        return
    password = getpass("Password: ")

    session_filename = f"{username}_session.json"
    state_filename = f"{username}_state.json"

    cl = Client()

    # two-factor callback used by some instagrapi versions
    def two_factor_callback(username_cb, two_factor_info=None):
        print("Two-factor authentication required.")
        code = input("Enter the 2FA / OTP code: ").strip()
        return code

    # Try to login with callbacks; handle common exceptions
    try:
        cl.login(username, password, two_factor_callback=two_factor_callback)
    except TwoFactorRequired as e:
        print("[*] TwoFactorRequired. Prompting for code.")
        code = input("Enter the 2FA / OTP code: ").strip()
        try:
            if hasattr(cl, "two_factor_login"):
                # Some versions want two_factor_login(code, two_factor_identifier)
                two_factor_identifier = None
                if hasattr(e, "two_factor_info") and isinstance(e.two_factor_info, dict):
                    two_factor_identifier = e.two_factor_info.get("two_factor_identifier")
                cl.two_factor_login(code, two_factor_identifier)
            else:
                cl.login(username, password, two_factor_callback=lambda u, info=None: code)
        except Exception as ex:
            print(f"[!] Failed 2FA step: {ex}")
            return
    except ChallengeRequired as e:
        print("[*] Challenge required. Instagram may have sent a code to email/phone.")
        code = input("If you received a challenge code, paste it here (or press Enter to abort): ").strip()
        if not code:
            print("[!] No challenge code provided. Aborting.")
            return
        try:
            if hasattr(cl, "challenge_code_handler"):
                cl.challenge_code_handler(code)
            elif hasattr(cl, "post_challenge_code"):
                cl.post_challenge_code(code)
            else:
                print("[!] This instagrapi version needs manual challenge handling. Try updating instagrapi.")
                return
        except Exception as ex:
            print(f"[!] Challenge submission failed: {ex}")
            return
    except BadPassword:
        print("[!] Bad password. Exiting.")
        return
    except Exception as e:
        # Last attempt: try login again interactively
        print(f"[*] Login raised: {e}. Trying interactive callback login once more.")
        try:
            cl.login(username, password, two_factor_callback=two_factor_callback)
        except Exception as ex:
            print(f"[!] Login failed again: {ex}")
            return

    # If logged in, dump settings and save session file
    try:
        try:
            settings = cl.dump_settings()
        except Exception:
            # fallback to attribute
            settings = getattr(cl, "settings", {}) or {}

        session_out = {
            "saved_at": int(time.time()),
            "username": username,
            "authorization_data": settings.get("authorization_data") if isinstance(settings, dict) else None,
            "settings": settings
        }
        save_json(session_filename, session_out)
        print(f"[+] Saved instagrapi session to {session_filename}")
    except Exception as e:
        print(f"[!] Failed to save session file: {e}")
        # still try to convert using cl.settings if available
        try:
            session_out = getattr(cl, "settings", {}) or {}
        except Exception:
            session_out = {}

    # Convert to playwright
    print("[*] Converting session to Playwright storage state...")
    playwright_state = convert_for_playwright(session_out if isinstance(session_out, dict) else {})
    if not playwright_state:
        # try inputting cl.dump_settings() directly if available
        try:
            raw = cl.dump_settings() if hasattr(cl, "dump_settings") else getattr(cl, "settings", {})
            playwright_state = convert_for_playwright(raw if isinstance(raw, dict) else {})
        except Exception:
            playwright_state = None

    if not playwright_state:
        print("[!] Conversion failed: could not find cookies in session data.")
        print("    Inspect the saved session file and adapt the converter for your instagrapi version.")
        return

    try:
        save_json(state_filename, playwright_state)
        print(f"[+] Saved Playwright state to {state_filename}")
        print("\nDone. Use in Playwright like:")
        print(f"  browser.new_context(storage_state='{state_filename}')")
    except Exception as e:
        print(f"[!] Failed to save Playwright state: {e}")

if __name__ == "__main__":
    main()