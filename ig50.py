# README
# Required packages:
# pip install playwright python-telegram-bot cryptography playwright-stealth instagrapi
# playwright install
# Set env vars:
# export BOT_TOKEN=your_token
# export OWNER_TG_ID=your_id
# Run: python spyther_bot.py
# For tests: manual as per acceptance criteria - /start, /login (use test IG account), /viewmyac, /attack (simulate), etc.

import argparse
import json
import os
import time
import random
import logging
import sqlite3
import re
from playwright.sync_api import sync_playwright
import base64
import hashlib
from cryptography.fernet import Fernet
from typing import Dict, List
import threading
import uuid
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes
import asyncio
from dotenv import load_dotenv
from playwright_stealth import stealth_sync
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, RateLimitError, LoginRequired

load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('instagram_gc_renamer.log'),
        logging.StreamHandler()
    ]
)

AUTHORIZED_FILE = 'authorized_users.json'
OWNER_TG_ID = int(os.environ.get('OWNER_TG_ID'))
BOT_TOKEN = os.environ.get('BOT_TOKEN')
USER_AGENT = "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36"

authorized_users = []  # list of {'id': int, 'username': str}
users_data: Dict[int, Dict] = {}  # unlocked data {'accounts': list, 'default': int}
users_keys: Dict[int, str] = {}  # secret keys in memory
users_pending: Dict[int, Dict] = {}  # pending challenges
users_tasks: Dict[int, List[Dict]] = {}  # tasks per user

def load_authorized():
    global authorized_users
    if os.path.exists(AUTHORIZED_FILE):
        with open(AUTHORIZED_FILE, 'r') as f:
            authorized_users = json.load(f)
    # Ensure owner is authorized
    if not any(u['id'] == OWNER_TG_ID for u in authorized_users):
        authorized_users.append({'id': OWNER_TG_ID, 'username': 'owner'})

load_authorized()

def save_authorized():
    with open(AUTHORIZED_FILE, 'w') as f:
        json.dump(authorized_users, f)

def derive_key(secret: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())

def encrypt_data(data: Dict, secret: str) -> bytes:
    f = Fernet(derive_key(secret))
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted: bytes, secret: str) -> Dict:
    f = Fernet(derive_key(secret))
    return json.loads(f.decrypt(encrypted).decode())

def save_user_data(user_id: int, data: Dict, secret: str):
    enc = encrypt_data(data, secret)
    with open(f'user_{user_id}.enc', 'wb') as f:
        f.write(enc)

def is_authorized(user_id: int) -> bool:
    return any(u['id'] == user_id for u in authorized_users)

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_TG_ID

def get_storage_state_from_instagrapi(settings: Dict):
    cl = Client()
    cl.set_settings(settings)
    cl.set_user_agent(USER_AGENT)
    cookies_dict = cl.session.cookies.get_dict()
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=USER_AGENT,
            viewport={'width': 1080, 'height': 2340},
            screen={'width': 1080, 'height': 2340},
            device_scale_factor=2.625,
            is_mobile=True,
            has_touch=True
        )
        cookies = [
            {
                'name': name,
                'value': value,
                'domain': '.instagram.com',
                'path': '/',
                'httpOnly': True,
                'secure': True
            } for name, value in cookies_dict.items()
        ]
        context.add_cookies(cookies)
        page = context.new_page()
        stealth_sync(page)
        page.evaluate("""() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'mimeTypes', { get: () => [1, 2, 3] });
            Object.defineProperty(navigator, 'userAgent', { get: () => 'Mozilla/5.0 (Linux; Android 10; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36' });
            Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
            Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
            window.chrome = { app: {}, runtime: {}, loadTimes: () => {}, csi: () => {} };
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
            const originalGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function() {
                const ctx = originalGetContext.apply(this, arguments);
                if (ctx) {
                    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                    CanvasRenderingContext2D.prototype.getImageData = function() {
                        const data = originalGetImageData.apply(this, arguments);
                        data.data[0] += Math.random() * 0.1;
                        return data;
                    };
                }
                return ctx;
            };
        }""")
        page.goto('https://www.instagram.com/', timeout=60000)
        page.wait_for_load_state('networkidle', timeout=60000)
        if 'accounts/login' in page.url or 'challenge' in page.url:
            raise ValueError("Session transfer failed, login required")
        storage_state = context.storage_state()
        browser.close()
    return storage_state

def instagrapi_login(username, password):
    cl = Client()
    cl.set_user_agent(USER_AGENT)
    try:
        cl.login(username, password)
    except (ChallengeRequired, TwoFactorRequired):
        raise ValueError("ERROR_004: Login challenge or 2FA required")
    except (PleaseWaitFewMinutes, RateLimitError):
        raise ValueError("ERROR_002: Rate limit exceeded")
    except Exception as e:
        raise ValueError(f"ERROR_007: Login failed - {str(e)}")
    return get_storage_state_from_instagrapi(cl.get_settings())

def list_group_chats(storage_state, username, password, max_groups=10):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(storage_state=storage_state if storage_state else {}, user_agent=USER_AGENT,
                                     viewport={'width': 1080, 'height': 2340}, screen={'width': 1080, 'height': 2340}, device_scale_factor=2.625, is_mobile=True, has_touch=True)
        page = context.new_page()
        stealth_sync(page)
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
        updated = False
        try:
            page.goto('https://www.instagram.com/direct/inbox/', timeout=60000)
            page.wait_for_load_state('networkidle')
            if 'accounts/login' in page.url:
                new_state = instagrapi_login(username, password)
                context.close()
                context = browser.new_context(storage_state=new_state, user_agent=USER_AGENT,
                                              viewport={'width': 1080, 'height': 2340}, screen={'width': 1080, 'height': 2340}, device_scale_factor=2.625, is_mobile=True, has_touch=True)
                page = context.new_page()
                stealth_sync(page)
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
                updated = True
                page.goto('https://www.instagram.com/direct/inbox/', timeout=60000)
                page.wait_for_load_state('networkidle')
            page.wait_for_selector('div[role="listitem"]', timeout=30000)
            chat_items = page.locator('div[role="listitem"]')
            groups = []
            for i in range(min(20, chat_items.count())):
                if len(groups) >= max_groups:
                    break
                try:
                    link_elem = chat_items.nth(i).locator('a')
                    href = link_elem.get_attribute('href', timeout=2000)
                    if not href or '/t/' not in href:
                        continue
                    url = 'https://www.instagram.com' + href
                    page.goto(url, timeout=60000)
                    page.wait_for_load_state('networkidle')
                    details_locator = page.locator("//div[@aria-label='Open the details pane of the chat']")
                    details_locator.wait_for(timeout=15000)
                    details_locator.click()
                    members_section = page.locator("//div[contains(text(),'Members')]")
                    if not members_section.is_visible():
                        page.go_back()
                        continue
                    members = page.locator("//div[contains(text(),'Members')] / following-sibling::div //span[@class='x1lliihq x1plvlek xryxfnj x1n2onr6 x193iq5w xeuugli x1fj9vlw x13faqbe x1vvkbs x1s928wv xhkezso x1gmr53x x1cpjm7i x1fgarty x1943h6x x1i0vuye xvs91rp xo1l8bm x5n08af x10wh9bi x1wdrske x8viiok x18hxmgj']")
                    member_names = [m.inner_text().strip() for m in members.all() if m.inner_text().strip() and m.inner_text().strip() != 'You']
                    if len(member_names) <= 1:
                        page.go_back()
                        continue
                    name_input = page.locator("//input[@placeholder='Group name']")
                    name = name_input.input_value(timeout=2000) if name_input.is_visible() else ''
                    if name:
                        display = name
                    else:
                        display = ', '.join(member_names[:3])
                    groups.append({'display': display, 'url': url})
                    page.go_back()
                except Exception as e:
                    logging.debug(f"Skipping chat {i}: {str(e)}")
                    continue
            new_state = context.storage_state() if updated else storage_state
            return groups, new_state
        finally:
            browser.close()

def run_rename_loop(task_dict, user_data, account, thread_url, names_list, task_id, stop_event, user_id, secret):
    ig_username = account['ig_username']
    password = account['password']
    storage_state = account.get('storage_state', None)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        task_dict['browser'] = browser
        context = browser.new_context(storage_state=storage_state, user_agent=USER_AGENT,
                                     viewport={'width': 1080, 'height': 2340}, screen={'width': 1080, 'height': 2340}, device_scale_factor=2.625, is_mobile=True, has_touch=True)
        task_dict['context'] = context
        page = context.new_page()
        stealth_sync(page)
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
        try:
            page.goto(thread_url, timeout=60000)
            page.wait_for_load_state('networkidle')
        except Exception as e:
            logging.error(f"Error navigating to thread URL: {str(e)}")
        if 'accounts/login' in page.url:
            logging.info("Login required. Performing login.")
            try:
                new_state = instagrapi_login(ig_username, password)
                context.close()
                context = browser.new_context(storage_state=new_state, user_agent=USER_AGENT,
                                              viewport={'width': 1080, 'height': 2340}, screen={'width': 1080, 'height': 2340}, device_scale_factor=2.625, is_mobile=True, has_touch=True)
                task_dict['context'] = context
                page = context.new_page()
                stealth_sync(page)
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
                page.goto(thread_url, timeout=60000)
                page.wait_for_load_state('networkidle')
                account['storage_state'] = new_state
                save_user_data(user_id, user_data, secret)
            except ValueError as e:
                logging.error(f"Re-login failed: {str(e)}")
                return

        # --- OPEN DETAILS PANE ---
        try:
            details_locator = page.locator("//div[@aria-label='Open the details pane of the chat']")
            details_locator.wait_for(timeout=15000)
            logging.debug("Clicking to open details pane")
            if not (details_locator.is_visible() and details_locator.is_enabled()):
                logging.debug("Details locator not visible/clickable, scrolling into view")
                details_locator.scroll_into_view_if_needed()
            details_locator.click()
            logging.info("Details pane opened")

            # === POPUP WATCHER ===
            watcher_timeout = 10.0
            poll_interval = 0.5
            start_watch = time.time()
            logging.debug("Starting Turn On Notifications watcher")
            while time.time() - start_watch < watcher_timeout and not stop_event.is_set():
                try:
                    notif_button = page.locator('button[tabindex="0"]:has-text("Turn On")')
                    if notif_button.count() > 0 and notif_button.is_visible():
                        if not notif_button.is_enabled():
                            notif_button.scroll_into_view_if_needed()
                            notif_button.click(force=True)
                        else:
                            notif_button.click()
                        logging.info("Clicked Turn On notifications")
                        break
                except:
                    pass
                time.sleep(poll_interval)
        except Exception as e:
            logging.error(f"Error opening details pane: {str(e)}")
            if 'accounts/login' in page.url:
                logging.info("Session expired. Re-logging in.")
                try:
                    new_state = instagrapi_login(ig_username, password)
                    context.close()
                    context = browser.new_context(storage_state=new_state, user_agent=USER_AGENT,
                                                  viewport={'width': 1080, 'height': 2340}, screen={'width': 1080, 'height': 2340}, device_scale_factor=2.625, is_mobile=True, has_touch=True)
                    task_dict['context'] = context
                    page = context.new_page()
                    stealth_sync(page)
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
                    details_locator.wait_for(timeout=15000)
                    if not (details_locator.is_visible() and details_locator.is_enabled()):
                        details_locator.scroll_into_view_if_needed()
                    details_locator.click()
                    account['storage_state'] = new_state
                    save_user_data(user_id, user_data, secret)
                except ValueError as e:
                    logging.error(f"Re-login failed: {str(e)}")
                    return

        # Setup names db
        db_file = f"names_{task_id}.db"
        conn = sqlite3.connect(db_file)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS names (name TEXT UNIQUE, used INTEGER DEFAULT 0)")
        for name in names_list:
            if name:
                try:
                    cur.execute("INSERT INTO names (name) VALUES (?)", (name,))
                except sqlite3.IntegrityError:
                    pass
        conn.commit()

        # --- ULTRA-FAST RENAME LOOP ---
        while not stop_event.is_set():
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
                if not (change_locator.is_visible() and change_locator.is_enabled()):
                    logging.debug("Change locator not visible/clickable, attempting to scroll")
                    try:
                        change_locator.scroll_into_view_if_needed()
                    except:
                        try:
                            scroll_el = page.locator(".x1xzczws > .xs83m0k")
                            if scroll_el.count() > 0:
                                scroll_el.scroll_into_view_if_needed()
                        except:
                            pass
                change_locator.click()

                input_locator = page.locator("//input[@placeholder='Group name']")
                input_locator.wait_for(timeout=15000)
                input_locator.fill(new_name)

                save_locator = page.locator("//div[@role='button' and contains(text(),'Save')]")
                save_locator.wait_for(timeout=15000)
                if not (save_locator.is_visible() and save_locator.is_enabled()):
                    save_locator.scroll_into_view_if_needed()
                try:
                    save_locator.click()
                except:
                    save_locator.click(force=True)

                cur.execute("UPDATE names SET used=1 WHERE name=?", (new_name,))
                conn.commit()
                logging.info(f"Successfully renamed to {new_name}")
            except Exception as e:
                logging.error(f"Error during rename to {new_name}: {str(e)}")
                if 'accounts/login' in page.url:
                    logging.info("Session expired during rename. Re-logging in.")
                    try:
                        new_state = instagrapi_login(ig_username, password)
                        context.close()
                        context = browser.new_context(storage_state=new_state, user_agent=USER_AGENT,
                                                      viewport={'width': 1080, 'height': 2340}, screen={'width': 1080, 'height': 2340}, device_scale_factor=2.625, is_mobile=True, has_touch=True)
                        task_dict['context'] = context
                        page = context.new_page()
                        stealth_sync(page)
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
                        account['storage_state'] = new_state
                        save_user_data(user_id, user_data, secret)
                    except ValueError as e:
                        logging.error(f"Re-login failed: {str(e)}")
                        return
                time.sleep(2)
                continue

        conn.close()
        try:
            os.remove(db_file)
        except:
            pass

USERNAME, PASSWORD, SECRET = range(3)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Welcome to Spyther's GC NC bot ⚡ type /help to see available commands")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return
    help_text = """
🌟 Available commands: 🌟
 /help ⚡ - Show this help
 /login 📱 - Login to Instagram account
 /otp 🔑 <code> - Send OTP if challenge pending
 /viewmyac 👀 - View your saved accounts
 /setig 🔄 <number> - Set default account
 /attack 💥 - Start renaming task
 /stop 🛑 - Stop your tasks
 /task 📋 - View ongoing tasks
    """
    if is_owner(user_id):
        help_text += """
Admin commands: 👑
 /add ➕ <tg_id> <@username> - Add authorized user
 /remove ➖ <tg_id> - Remove authorized user
 /users 📜 - List authorized users
        """
    await update.message.reply_text(help_text)

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return ConversationHandler.END
    await update.message.reply_text("📱 Enter Instagram username: 📱")
    return USERNAME

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['ig_username'] = update.message.text.strip()
    await update.message.reply_text("🔒 Enter password: 🔒")
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['password'] = update.message.text.strip()
    await update.message.reply_text("🗝️ Enter a secret key to encrypt your credentials (any phrase): 🗝️")
    return SECRET

async def get_secret(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    secret = update.message.text.strip()
    ig_username = context.user_data['ig_username']
    password = context.user_data['password']
    await update.message.reply_text("🔄 Logging in... 🔄")

    def do_login():
        cl = Client()
        cl.set_user_agent(USER_AGENT)
        try:
            # ---- Proper init for instagrapi ≥ 2.x ----
            cl.init()
            cl.delay_range = [1, 3]

            # ✅ Handle API rename (http → private)
            http_client = getattr(cl, "http", None) or getattr(cl, "private", None) or getattr(cl, "_http", None)
            if http_client:
                http_client.get("https://www.instagram.com/")
                http_client.get("https://www.instagram.com/accounts/login/")

            # Warm-up API
            cl.get_timeline_feed()
            cl.pre_login_flow()

            # ✅ Perform login
            result = cl.login(ig_username, password)

            # 🔥 FIX: Detect if response is empty or HTML instead of JSON
            if not result:
                last_resp = getattr(cl, "last_response", None)
                if last_resp is not None:
                    text = last_resp.text if hasattr(last_resp, "text") else str(last_resp)
                    if text.strip().startswith("<!DOCTYPE html>") or "<html" in text.lower():
                        raise ValueError("Instagram returned HTML instead of JSON (likely blocked or unsupported Python/Instagrapi version)")
                raise ValueError("Empty login response from API")

            cl.post_login_flow()
            storage_state = get_storage_state_from_instagrapi(cl.get_settings())
            return storage_state, None

        except Exception as e:
            try:
                print("RAW LOGIN RESPONSE:", getattr(cl, "last_response", None).text)
            except Exception:
                pass
            raise e

    try:
        state, pending = await asyncio.to_thread(do_login)
        if pending:
            users_pending[user_id] = {'type': pending['type'], 'settings': pending['settings'], 'ig_username': ig_username, 'password': password, 'secret': secret}
            await update.message.reply_text("⚠️ Instagram requires an OTP or challenge. Send it using /otp 123456. ⚠️")
            return ConversationHandler.END
        # Success
        if user_id in users_data:
            data = users_data[user_id]
        else:
            data = {'accounts': [], 'default': None}
        # Check if username exists, update or add
        for i, acc in enumerate(data['accounts']):
            if acc['ig_username'] == ig_username:
                data['accounts'][i] = {'ig_username': ig_username, 'password': password, 'storage_state': state}
                data['default'] = i
                break
        else:
            data['accounts'].append({'ig_username': ig_username, 'password': password, 'storage_state': state})
            data['default'] = len(data['accounts']) - 1
        save_user_data(user_id, data, secret)
        users_data[user_id] = data
        users_keys[user_id] = secret
        await update.message.reply_text("✅ Login successful and saved securely! 🎉")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Login failed: {str(e)} ⚠️")
    return ConversationHandler.END

async def otp_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return
    if user_id not in users_pending:
        await update.message.reply_text("❌ No challenge is pending. ❌")
        return
    if not context.args:
        await update.message.reply_text("❗ Provide the OTP code. ❗")
        return
    code = ' '.join(context.args)
    pending = users_pending[user_id]
    await update.message.reply_text("🔄 Submitting OTP... 🔄")

    def submit_otp():
        cl = Client()
        cl.set_settings(pending['settings'])
        cl.set_user_agent(USER_AGENT)
        try:
            if pending['type'] == '2fa':
                cl.login(pending['ig_username'], pending['password'], verification_code=code)
            elif pending['type'] == 'challenge':
                cl.challenge_resolve(cl.last_json, security_code=code)
            storage_state = get_storage_state_from_instagrapi(cl.get_settings())
            return storage_state, None
        except Exception as e:
            return None, str(e)

    state, error = await asyncio.to_thread(submit_otp)
    if error:
        await update.message.reply_text(f"⚠️ Failed to submit OTP: {error} ⚠️")
        return
    # Success
    ig_username = pending['ig_username']
    password = pending['password']
    secret = pending['secret']
    if user_id in users_data:
        data = users_data[user_id]
    else:
        data = {'accounts': [], 'default': None}
    for i, acc in enumerate(data['accounts']):
        if acc['ig_username'] == ig_username:
            data['accounts'][i] = {'ig_username': ig_username, 'password': password, 'storage_state': state}
            data['default'] = i
            break
    else:
        data['accounts'].append({'ig_username': ig_username, 'password': password, 'storage_state': state})
        data['default'] = len(data['accounts']) - 1
    save_user_data(user_id, data, secret)
    users_data[user_id] = data
    users_keys[user_id] = secret
    del users_pending[user_id]
    await update.message.reply_text("✅ Login successful and saved securely! 🎉")

async def viewmyac(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return
    if user_id not in users_data:
        await update.message.reply_text("❌ You haven't saved any account. Use /login to save one. ❌")
        return
    data = users_data[user_id]
    msg = "👀 Your saved account list 👀\n"
    for i, acc in enumerate(data['accounts']):
        default = " (default) ⭐" if data['default'] == i else ""
        msg += f"{i+1}. {acc['ig_username']}{default}\n"
    await update.message.reply_text(msg)

async def setig(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("❗ Usage: /setig <number> ❗")
        return
    num = int(context.args[0]) - 1
    if user_id not in users_data:
        await update.message.reply_text("❌ No accounts saved. ❌")
        return
    data = users_data[user_id]
    if num < 0 or num >= len(data['accounts']):
        await update.message.reply_text("⚠️ Invalid number. ⚠️")
        return
    data['default'] = num
    save_user_data(user_id, data, users_keys[user_id])
    acc = data['accounts'][num]['ig_username']
    await update.message.reply_text(f"✅ {num+1}. {acc} now is your default account. ⭐")

SELECT_THREAD, NAMES = range(2)

async def attack_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return ConversationHandler.END
    if user_id not in users_data:
        await update.message.reply_text("❗ Please /login first. ❗")
        return ConversationHandler.END
    data = users_data[user_id]
    if data['default'] is None:
        await update.message.reply_text("⚠️ No default account set. Use /login or /setig. ⚠️")
        return ConversationHandler.END
    account = data['accounts'][data['default']]
    await update.message.reply_text("🔍 Fetching last 10 GC threads... 🔍")
    groups, new_state = await asyncio.to_thread(list_group_chats, account['storage_state'], account['ig_username'], account['password'])
    if new_state != account['storage_state']:
        account['storage_state'] = new_state
        save_user_data(user_id, data, users_keys[user_id])
    if not groups:
        await update.message.reply_text("❌ No group chats found. ❌")
        return ConversationHandler.END
    msg = "🔢 Select a thread by number: 🔢\n"
    for i, g in enumerate(groups):
        msg += f"{i+1}. {g['display']}\n"
    await update.message.reply_text(msg)
    context.user_data['groups'] = groups
    return SELECT_THREAD

async def select_thread(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not update.message.text.isdigit():
        await update.message.reply_text("❗ Please send a number. ❗")
        return SELECT_THREAD
    num = int(update.message.text) - 1
    groups = context.user_data.get('groups', [])
    if num < 0 or num >= len(groups):
        await update.message.reply_text("⚠️ Invalid number. ⚠️")
        return SELECT_THREAD
    selected = groups[num]
    context.user_data['selected_gc'] = selected
    await update.message.reply_text("📝 Send text in this format to name gc : group 1,group 2,group 3 📝")
    return NAMES

async def get_names(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    user_id = update.effective_user.id
    text = update.message.text.strip()
    names_list = [n.strip() for n in re.split(r'[,\n]', text) if n.strip()]
    if not names_list:
        await update.message.reply_text("⚠️ No names provided. ⚠️")
        return NAMES
    selected = context.user_data['selected_gc']
    data = users_data[user_id]
    secret = users_keys[user_id]
    account = data['accounts'][data['default']]
    if len(users_tasks.get(user_id, [])) >= 3:
        await update.message.reply_text("⚠️ Already 3 tasks are currently processing. Type /stop to stop tasks then retry. ⚠️")
        return ConversationHandler.END
    await update.message.reply_text("🔄 Processing your task backend... 🔄")
    # Fake progress
    for percent in range(5, 101, 5):
        bar = '█' * (percent // 10) + '▒' * (10 - percent // 10)
        await update.message.reply_text(f"⏳ Please wait processing your task ⏳\n{bar} {percent}%")
        await asyncio.sleep(5)
    await update.message.reply_text("💥 Changing gc name! To stop this task type /stop. 💥")
    # Start task
    stop_event = threading.Event()
    task_id = uuid.uuid4().hex[:8]
    task = {'id': task_id, 'stop_event': stop_event, 'gc_display': selected['display'], 'account': account['ig_username'], 'thread_url': selected['url']}
    t = threading.Thread(target=run_rename_loop, args=(task, data, account, selected['url'], names_list, task_id, stop_event, user_id, secret))
    task['thread'] = t
    t.start()
    users_tasks.setdefault(user_id, []).append(task)
    return ConversationHandler.END

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return
    if is_owner(user_id):
        # Stop all
        for uid in list(users_tasks.keys()):
            tasks = users_tasks[uid]
            for task in tasks:
                task['stop_event'].set()
                if 'context' in task:
                    try:
                        task['context'].close()
                    except:
                        pass
                if 'browser' in task:
                    try:
                        task['browser'].close()
                    except:
                        pass
                task['thread'].join(timeout=15)
            del users_tasks[uid]
        await update.message.reply_text("🛑 Stopping all tasks globally! 🛑")
    else:
        if user_id not in users_tasks or not users_tasks[user_id]:
            await update.message.reply_text("❌ No tasks running. ❌")
            return
        tasks = users_tasks[user_id]
        for task in tasks:
            task['stop_event'].set()
            if 'context' in task:
                try:
                    task['context'].close()
                except:
                    pass
            if 'browser' in task:
                try:
                    task['browser'].close()
                except:
                    pass
            task['thread'].join(timeout=15)
        del users_tasks[user_id]
        await update.message.reply_text("🛑 Stopping all task! 🛑")

async def task_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_authorized(user_id):
        await update.message.reply_text("⚠️ You are not authorised to use, dm owner to gain access @spyther ! ⚠️")
        return
    if user_id not in users_tasks or not users_tasks[user_id]:
        await update.message.reply_text("❌ No ongoing tasks. ❌")
        return
    tasks = users_tasks[user_id]
    msg = f"📋 Ongoing tasks {len(tasks)}/3 📋\n"
    for i, task in enumerate(tasks):
        preview = task['gc_display'][:10] + '...' if len(task['gc_display']) > 10 else task['gc_display']
        msg += f"{i+1}. Task {task['id']} with account {task['account']}, GC {preview}\n"
    await update.message.reply_text(msg)

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ you are not an admin ⚠️")
        return
    if len(context.args) != 2:
        await update.message.reply_text("❗ Usage: /add <tg_id> <@username> ❗")
        return
    try:
        tg_id = int(context.args[0])
        username = context.args[1].lstrip('@')
        if any(u['id'] == tg_id for u in authorized_users):
            await update.message.reply_text("❗ User already added. ❗")
            return
        authorized_users.append({'id': tg_id, 'username': username})
        save_authorized()
        await update.message.reply_text(f"➕ Added {tg_id} as authorized user. ➕")
    except:
        await update.message.reply_text("⚠️ Invalid tg_id. ⚠️")

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ you are not an admin ⚠️")
        return
    if not context.args or not context.args[0].isdigit():
        await update.message.reply_text("❗ Usage: /remove <tg_id> ❗")
        return
    tg_id = int(context.args[0])
    global authorized_users
    authorized_users = [u for u in authorized_users if u['id'] != tg_id]
    save_authorized()
    await update.message.reply_text(f"➖ Removed {tg_id} from authorized users. ➖")

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_owner(user_id):
        await update.message.reply_text("⚠️ you are not an admin ⚠️")
        return
    if not authorized_users:
        await update.message.reply_text("❌ No authorized users. ❌")
        return
    msg = "📜 Authorized users: 📜\n"
    for u in authorized_users:
        msg += f"{u['id']} @{u['username']}\n"
    await update.message.reply_text(msg)

def main_bot():
    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("otp", otp_command))
    application.add_handler(CommandHandler("viewmyac", viewmyac))
    application.add_handler(CommandHandler("setig", setig))
    application.add_handler(CommandHandler("stop", stop))
    application.add_handler(CommandHandler("task", task_command))
    application.add_handler(CommandHandler("add", add_user))
    application.add_handler(CommandHandler("remove", remove_user))
    application.add_handler(CommandHandler("users", list_users))

    conv_login = ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            SECRET: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_secret)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_login)

    conv_attack = ConversationHandler(
        entry_points=[CommandHandler("attack", attack_start)],
        states={
            SELECT_THREAD: [MessageHandler(filters.TEXT & ~filters.COMMAND, select_thread)],
            NAMES: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_names)],
        },
        fallbacks=[],
    )
    application.add_handler(conv_attack)

    application.run_polling()

if __name__ == "__main__":
    main_bot()