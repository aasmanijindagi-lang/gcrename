"""
Instagram Group Chat Renamer

Usage examples:
python instagram_gc_renamer.py --username your_username --password your_password --thread-url https://www.instagram.com/direct/t/123/ --names "Spyther GC ✨,Spyther Power 💣,Spyther ⚡,Spyther Ultra 🌟" --headless false

Install instructions:
pip install playwright
playwright install
"""
import argparse
import json
import os
import time
import random
import logging
import sqlite3
import re
from playwright.sync_api import sync_playwright

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instagram_gc_renamer.log'),
        logging.StreamHandler()
    ]
)

def main():
    parser = argparse.ArgumentParser(description="Instagram Group Chat Renamer")
    parser.add_argument('--username', required=True, help='Instagram username')
    parser.add_argument('--password', required=True, help='Instagram password')
    parser.add_argument('--thread-url', required=True, help='Target thread URL')
    parser.add_argument('--names', default='', help='Comma or newline-separated list of names')
    parser.add_argument('--headless', default='true', help='Run in headless mode (true/false)')
    args = parser.parse_args()

    headless = args.headless.lower() == 'true'
    state_file = f"{args.username}_state.json"

    conn = sqlite3.connect('names.db')
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS names (name TEXT UNIQUE, used INTEGER DEFAULT 0)")
    conn.commit()

    if args.names:
        names_list = [n.strip() for n in re.split(r'[,\n]', args.names) if n.strip()]
        cur.execute("DELETE FROM names")
        conn.commit()
        for name in names_list:
            if name:
                try:
                    cur.execute("INSERT INTO names (name) VALUES (?)", (name,))
                    conn.commit()
                    logging.info(f"Added name to queue: {name}")
                except sqlite3.IntegrityError:
                    logging.debug(f"Name already exists: {name}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        if os.path.exists(state_file):
            logging.debug(f"Loading storage state from {state_file}")
            with open(state_file, 'r') as f:
                storage_state = json.load(f)
            context = browser.new_context(storage_state=storage_state)
        else:
            context = browser.new_context()

        page = context.new_page()
        logging.debug(f"Navigating to thread URL: {args.thread_url}")
        try:
            page.goto(args.thread_url, timeout=60000)
        except Exception as e:
            logging.error(f"Error navigating to thread URL: {str(e)}")

        if 'accounts/login' in page.url:
            logging.info("Login required. Performing login.")
            perform_login(page, args.username, args.password)
            try:
                page.goto(args.thread_url, timeout=60000)
            except Exception as e:
                logging.error(f"Error navigating to thread URL after login: {str(e)}")
            context.storage_state(path=state_file)
            logging.debug(f"Saved storage state to {state_file}")

        # --- OPEN DETAILS PANE ---
        try:
            details_locator = page.locator("//div[@aria-label='Open the details pane of the chat']")
            details_locator.wait_for(timeout=15000)
            logging.debug("Clicking to open details pane")
            # Conditional scroll: only if not visible or not enabled
            try:
                if not (details_locator.is_visible() and details_locator.is_enabled()):
                    logging.debug("Details locator not visible/clickable, scrolling into view")
                    details_locator.scroll_into_view_if_needed()
            except Exception:
                # If checks fail, attempt scroll to be safe
                try:
                    details_locator.scroll_into_view_if_needed()
                except Exception:
                    pass
            details_locator.click()
            logging.info("Details pane opened")

            # === POPUP WATCHER: START AFTER DETAILS PANE OPEN ===
            # Very fast polling (0.5s). Click only the stable selector button[tabindex="0"]:has-text("Turn On").
            watcher_timeout = 60.0   # seconds total to watch after details pane opens
            poll_interval = 0.5     # seconds between checks
            start_watch = time.time()
            logging.debug("Starting Turn On Notifications watcher (after details pane open)")
            while time.time() - start_watch < watcher_timeout:
                try:
                    notif_button = page.locator('button[tabindex="0"]:has-text("Turn On")')
                    # If the locator exists and is visible, attempt immediate click
                    if notif_button.count() and notif_button.is_visible():
                        try:
                            # If not enabled, try scroll then force click as a last resort.
                            if not notif_button.is_enabled():
                                try:
                                    notif_button.scroll_into_view_if_needed()
                                except Exception:
                                    pass
                                notif_button.click(force=True)
                            else:
                                # Normal immediate click
                                notif_button.click()
                            logging.info("Clicked Turn On notifications")
                            break
                        except Exception as e_click:
                            logging.debug(f"Failed to click Turn On directly: {e_click}")
                            # fallback: try JS click on the element handle
                            try:
                                handle = notif_button.element_handle()
                                if handle:
                                    page.evaluate("(el) => el.click()", handle)
                                    logging.info("Clicked Turn On notifications via JS fallback")
                                    break
                            except Exception:
                                pass
                    # else: not present yet
                except Exception:
                    # ignore and retry
                    pass
                time.sleep(poll_interval)

        except Exception as e:
            logging.error(f"Error opening details pane: {str(e)}")
            if 'accounts/login' in page.url:
                logging.info("Session expired. Re-logging in.")
                perform_login(page, args.username, args.password)
                try:
                    page.goto(args.thread_url, timeout=60000)
                except Exception as e:
                    logging.error(f"Error navigating to thread URL after re-login: {str(e)}")
                context.storage_state(path=state_file)
                details_locator.wait_for(timeout=15000)
                # conditional scroll again
                try:
                    if not (details_locator.is_visible() and details_locator.is_enabled()):
                        details_locator.scroll_into_view_if_needed()
                except Exception:
                    pass
                details_locator.click()

        # --- ULTRA-FAST RENAME LOOP ---
        while True:
            cur.execute("SELECT name FROM names WHERE used=0 LIMIT 1")
            row = cur.fetchone()
            if not row:
                logging.info("All names used. Resetting queue.")
                cur.execute("UPDATE names SET used=0")
                conn.commit()
                continue

            new_name = row[0]
            try:
                logging.debug(f"Starting rename to: {new_name}")

                change_locator = page.locator("//div[@aria-label='Change group name']")
                change_locator.wait_for(timeout=15000)
                logging.debug("Clicking change group name")
                # Conditional scroll only if not visible/clickable
                try:
                    if not (change_locator.is_visible() and change_locator.is_enabled()):
                        logging.debug("Change locator not visible/clickable, attempting to scroll a likely container")
                        try:
                            change_locator.scroll_into_view_if_needed()
                        except Exception:
                            # fallback: try a known container
                            try:
                                scroll_el = page.locator(".x1xzczws > .xs83m0k")
                                if not (scroll_el.is_visible() and scroll_el.is_enabled()):
                                    scroll_el.scroll_into_view_if_needed()
                            except Exception:
                                pass
                except Exception:
                    # If checking properties failed, attempt a safe scroll attempt
                    try:
                        change_locator.scroll_into_view_if_needed()
                    except Exception:
                        pass

                # Open the dialog / edit UI
                change_locator.click()

                # Locate the input
                input_locator = page.locator("//input[@placeholder='Group name']")
                input_locator.wait_for(timeout=20000)

                # ---------- INSTANT REPLACE: NO CURSOR, NO TYPING ----------
                # Set the input value directly via JS (no focus, no typing) and dispatch events
                try:
                    input_locator.fill(new_name)
                except Exception as e_fill:
                    logging.error(f"Failed to set new name by any method: {e_fill}")
                    raise

                # ---------- INSTANT SAVE: CLICK IMMEDIATELY (NO WAIT) ----------
                save_locator = page.locator("//div[@role='button' and contains(text(),'Save')]")
                save_locator.wait_for(timeout=15000)
                try:
                    if not (save_locator.is_visible() and save_locator.is_enabled()):
                        try:
                            save_locator.scroll_into_view_if_needed()
                        except Exception:
                            pass
                    # Click immediately. Use force click as a last resort to ensure instant action.
                    try:
                        save_locator.click()
                    except Exception as e_click:
                        logging.debug(f"Normal save click failed, trying force click: {e_click}")
                        try:
                            save_locator.click(force=True)
                        except Exception:
                            # final fallback: JS click
                            try:
                                handle = save_locator.element_handle()
                                if handle:
                                    page.evaluate("(el) => el.click()", handle)
                                else:
                                    raise
                            except Exception as e_js:
                                logging.error(f"Save click failed by all methods: {e_js}")
                                raise
                except Exception as e_save:
                    logging.error(f"Error clicking Save for {new_name}: {e_save}")
                    raise

                # Mark as used immediately
                cur.execute("UPDATE names SET used=1 WHERE name=?", (new_name,))
                conn.commit()
                logging.info(f"Successfully renamed to {new_name}")

            except Exception as e:
                logging.error(f"Error during rename to {new_name}: {str(e)}")
                if 'accounts/login' in page.url:
                    logging.info("Session expired during rename. Re-logging in.")
                    perform_login(page, args.username, args.password)
                    context.storage_state(path=state_file)
                time.sleep(2)

        conn.close()
        browser.close()

def perform_login(page, username, password):
    try:
        # Anti-detection measures to make the browser appear more realistic
        page.evaluate("""() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            window.chrome = { app: {}, runtime: {} };
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                Promise.resolve({ state: 'denied' }) :
                originalQuery(parameters)
            );
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Google Inc. (Intel)';
                if (parameter === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)';
                return getParameter.call(this, parameter);
            };
        }""")

        # Wait for username input
        username_locator = page.locator('input[name="username"]')
        username_locator.wait_for(state='visible', timeout=10000)

        # Human-like focus and typing
        username_locator.focus()
        time.sleep(random.uniform(0.5, 1.5))
        for char in username:
            username_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        # Wait for password input
        password_locator = page.locator('input[name="password"]')
        password_locator.wait_for(state='visible', timeout=10000)

        # Human-like focus and typing for password
        time.sleep(random.uniform(0.5, 1.5))
        password_locator.focus()
        time.sleep(random.uniform(0.3, 0.8))
        for char in password:
            password_locator.press(char)
            time.sleep(random.uniform(0.05, 0.15))

        # Random delay before submit
        time.sleep(random.uniform(1.0, 2.5))

        # Submit button
        submit_locator = page.locator('button[type="submit"]')
        submit_locator.wait_for(state='visible', timeout=10000)
        if not submit_locator.is_enabled():
            raise Exception("Submit button not enabled")
        submit_locator.click()

        # Wait for navigation and handle outcomes
        try:
            page.wait_for_url(lambda url: 'accounts/login' not in url and 'challenge' not in url and 'two_factor' not in url, timeout=60000)
            
            # Check for inline error messages
            if page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                if 'incorrect' in error_text or 'wrong' in error_text:
                    raise ValueError("ERROR_001: Invalid credentials")
                elif 'wait' in error_text or 'few minutes' in error_text or 'too many' in error_text:
                    raise ValueError("ERROR_002: Rate limit exceeded")
                else:
                    raise ValueError(f"ERROR_003: Login error - {error_text}")
        except TimeoutError:
            current_url = page.url
            page_content = page.content().lower()
            if 'challenge' in current_url:
                raise ValueError("ERROR_004: Login challenge required")
            elif 'two_factor' in current_url or 'verify' in current_url:
                raise ValueError("ERROR_005: 2FA verification required")
            elif '429' in page_content or 'rate limit' in page_content or 'too many requests' in page_content:
                raise ValueError("ERROR_002: Rate limit exceeded")
            elif page.locator('[role="alert"]').count() > 0:
                error_text = page.locator('[role="alert"]').inner_text().lower()
                raise ValueError(f"ERROR_006: Login failed - {error_text}")
            else:
                raise ValueError("ERROR_007: Login timeout or unknown error")

        logging.info("Login successful")
    except Exception as e:
        logging.error(f"Login failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()
