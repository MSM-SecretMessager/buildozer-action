import os, base64, threading, json
import requests
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.properties import StringProperty, ListProperty
from kivy.clock import Clock

SETTINGS_FILE = "settings.json"
KEY_FILE = "user_keys.json"

def get_server_url():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            return json.load(f).get("server_url", "")
    return ""

def save_server_url(url):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump({"server_url": url}, f)

# ---------- Криптография ----------
def generate_keys():
    x_priv = x25519.X25519PrivateKey.generate()
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    return {"x_priv": x_priv, "x_pub": x_priv.public_key(),
            "ed_priv": ed_priv, "ed_pub": ed_priv.public_key()}

def serialize_keys(keys):
    return {
        "x_priv": keys["x_priv"].private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()).hex(),
        "x_pub": keys["x_pub"].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex(),
        "ed_priv": keys["ed_priv"].private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()).hex(),
        "ed_pub": keys["ed_pub"].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw).hex()
    }

def load_keys(data):
    keys = {}
    keys["x_priv"] = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(data["x_priv"]))
    keys["x_pub"] = keys["x_priv"].public_key()
    keys["ed_priv"] = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["ed_priv"]))
    keys["ed_pub"] = keys["ed_priv"].public_key()
    return keys

def encrypt_message(text, sender_keys, recip_x_pub_hex):
    recip_x_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(recip_x_pub_hex))
    shared = sender_keys["x_priv"].exchange(recip_x_pub)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'messenger-aes-key').derive(shared)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, text.encode(), None)
    sig = sender_keys["ed_priv"].sign(ct)
    return base64.b64encode(nonce + ct + sig).decode()

def decrypt_message(packet_b64, recv_keys, sender_x_pub_hex, sender_ed_pub_hex):
    raw = base64.b64decode(packet_b64)
    nonce, ct, sig = raw[:12], raw[12:-64], raw[-64:]
    sender_x_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(sender_x_pub_hex))
    shared = recv_keys["x_priv"].exchange(sender_x_pub)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'messenger-aes-key').derive(shared)
    aesgcm = AESGCM(aes_key)
    plain = aesgcm.decrypt(nonce, ct, None)
    sender_ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender_ed_pub_hex))
    sender_ed_pub.verify(sig, ct)
    return plain.decode()

# ---------- Экраны ----------
class SettingsScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        layout.add_widget(Label(text="Адрес сервера", font_size=20))
        self.url_input = TextInput(text=get_server_url(), hint_text="http://192.168.1.100:5000", multiline=False)
        layout.add_widget(self.url_input)
        btn = Button(text="Сохранить", size_hint=(1, 0.3))
        btn.bind(on_press=self.save)
        layout.add_widget(btn)
        self.add_widget(layout)

    def save(self, instance):
        url = self.url_input.text.strip().rstrip('/')
        if not url.startswith('http'):
            self.url_input.text = "Должен начинаться с http://"
            return
        save_server_url(url)
        App.get_running_app().server_url = url
        self.manager.current = 'login'

class LoginScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        layout.add_widget(Label(text="Имя пользователя", font_size=20))
        self.username_input = TextInput(hint_text="Имя", multiline=False)
        layout.add_widget(self.username_input)
        layout.add_widget(Label(text="Пароль (только для админа)", font_size=14))
        self.password_input = TextInput(hint_text="Пароль", multiline=False, password=True)
        layout.add_widget(self.password_input)
        btn = Button(text="Войти", size_hint=(1, 0.3))
        btn.bind(on_press=self.do_login)
        layout.add_widget(btn)
        self.status = Label(text="")
        layout.add_widget(self.status)
        self.add_widget(layout)

    def do_login(self, instance):
        username = self.username_input.text.strip()
        password = self.password_input.text.strip()
        if not username:
            self.status.text = "Введите имя"
            return
        app = App.get_running_app()
        if username == "admin":
            if not password:
                self.status.text = "Введите пароль"
                return
            self.try_admin_login(username, password)
            return
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE) as f:
                saved = json.load(f)
            if username in saved:
                app.user_keys = load_keys(saved[username])
                app.username = username
                self.register_on_server(username, app.user_keys)
                return
        keys = generate_keys()
        app.user_keys = keys
        app.username = username
        saved = {}
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE) as f:
                saved = json.load(f)
        saved[username] = serialize_keys(keys)
        with open(KEY_FILE, 'w') as f:
            json.dump(saved, f)
        self.register_on_server(username, keys)

    def try_admin_login(self, username, password):
        app = App.get_running_app()
        def login():
            try:
                r = requests.post(f"{app.server_url}/admin/login", json={
                    "username": username, "password": password
                })
                if r.status_code == 200:
                    app.admin_secret = r.json()["secret"]
                    Clock.schedule_once(lambda dt: setattr(self.manager, 'current', 'admin'))
                else:
                    Clock.schedule_once(lambda dt: setattr(self.status, 'text', "Неверный пароль"))
            except Exception as e:
                Clock.schedule_once(lambda dt: setattr(self.status, 'text', f"Нет связи: {e}"))
        threading.Thread(target=login, daemon=True).start()

    def register_on_server(self, username, keys):
        app = App.get_running_app()
        def register():
            try:
                r = requests.post(f"{app.server_url}/register", json={
                    "username": username,
                    "x25519_pub": keys["x_pub"].public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw).hex(),
                    "ed25519_pub": keys["ed_pub"].public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw).hex()
                })
                if r.status_code == 201:
                    Clock.schedule_once(lambda dt: setattr(self.manager, 'current', 'contacts'))
                else:
                    msg = r.json().get("error", "Ошибка")
                    Clock.schedule_once(lambda dt: setattr(self.status, 'text', f"Ошибка: {msg}"))
            except Exception as e:
                Clock.schedule_once(lambda dt: setattr(self.status, 'text', f"Нет связи: {e}"))
        threading.Thread(target=register, daemon=True).start()

class ContactListScreen(Screen):
    users = ListProperty([])

    def on_enter(self):
        self.refresh()

    def refresh(self):
        app = App.get_running_app()
        def fetch():
            try:
                r = requests.get(f"{app.server_url}/users")
                if r.status_code == 200:
                    all_users = list(r.json().keys())
                    if app.username in all_users:
                        all_users.remove(app.username)
                    if "admin" in all_users:
                        all_users.remove("admin")
                    Clock.schedule_once(lambda dt: setattr(self, 'users', all_users))
            except Exception as e:
                print("Ошибка загрузки контактов:", e)
        threading.Thread(target=fetch, daemon=True).start()

    def on_users(self, instance, value):
        self.ids.container.clear_widgets()
        for user in value:
            btn = Button(text=user, size_hint_y=None, height=50)
            btn.bind(on_press=lambda inst, u=user: self.open_chat(u))
            self.ids.container.add_widget(btn)

    def open_chat(self, username):
        app = App.get_running_app()
        app.chat_screen.recipient = username
        self.manager.current = 'chat'

class ChatScreen(Screen):
    recipient = StringProperty("")

    def on_enter(self):
        self.ids.chat_history.clear_widgets()
        self.check_event = Clock.schedule_interval(self.check_messages, 2)

    def on_leave(self):
        if hasattr(self, 'check_event'):
            self.check_event.cancel()

    def send_message(self):
        text = self.ids.msg_input.text.strip()
        if not text or not self.recipient:
            return
        app = App.get_running_app()
        def send():
            try:
                r = requests.get(f"{app.server_url}/users")
                contacts = r.json()
                if self.recipient not in contacts:
                    self.show_error("Пользователь не найден")
                    return
                recip_x = contacts[self.recipient]["x25519_pub"]
                enc = encrypt_message(text, app.user_keys, recip_x)
                r2 = requests.post(f"{app.server_url}/send", json={
                    "from": app.username, "to": self.recipient, "data": enc
                })
                if r2.status_code == 200:
                    Clock.schedule_once(lambda dt: self.add_message("Вы", text))
                    Clock.schedule_once(lambda dt: setattr(self.ids.msg_input, 'text', ''))
                else:
                    self.show_error("Ошибка отправки")
            except Exception as e:
                self.show_error(str(e))
        threading.Thread(target=send, daemon=True).start()

    def check_messages(self, dt):
        app = App.get_running_app()
        def fetch():
            try:
                r = requests.get(f"{app.server_url}/check_messages/{app.username}")
                if r.status_code == 200:
                    msgs = r.json()
                    for m in msgs:
                        sender = m["from"]
                        if sender != self.recipient and sender != app.username:
                            continue
                        contacts = requests.get(f"{app.server_url}/users").json()
                        if sender not in contacts:
                            continue
                        s_x = contacts[sender]["x25519_pub"]
                        s_ed = contacts[sender]["ed25519_pub"]
                        try:
                            plain = decrypt_message(m["data"], app.user_keys, s_x, s_ed)
                            Clock.schedule_once(lambda dt, s=sender, t=plain: self.add_message(s, t))
                        except Exception as e:
                            print("Ошибка расшифровки:", e)
            except Exception as e:
                print("Ошибка проверки:", e)
        threading.Thread(target=fetch, daemon=True).start()

    def add_message(self, sender, text):
        self.ids.chat_history.add_widget(Label(text=f"[{sender}] {text}", size_hint_y=None, height=30))

    def show_error(self, msg):
        Clock.schedule_once(lambda dt: self.add_message("Система", f"Ошибка: {msg}"))

class AdminScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)
        layout.add_widget(Label(text="Панель администратора", font_size=24))
        self.info_label = Label(text="")
        layout.add_widget(self.info_label)
        btn = Button(text="Обновить статистику", size_hint=(1, 0.2))
        btn.bind(on_press=lambda x: self.refresh_stats())
        layout.add_widget(btn)
        self.add_widget(layout)
        self.refresh_stats()

    def refresh_stats(self):
        app = App.get_running_app()
        def fetch():
            try:
                r = requests.get(f"{app.server_url}/admin/stats",
                                 headers={"X-Admin-Secret": app.admin_secret})
                if r.status_code == 200:
                    data = r.json()
                    text = f"Пользователей онлайн: {data['users_online']}\n"
                    text += "Список:\n"
                    for u in data['user_list']:
                        text += f"  - {u}\n"
                    text += "Непрочитанных сообщений:\n"
                    for u, cnt in data['pending_messages'].items():
                        text += f"  {u}: {cnt}\n"
                    Clock.schedule_once(lambda dt: setattr(self.info_label, 'text', text))
            except Exception as e:
                Clock.schedule_once(lambda dt: setattr(self.info_label, 'text', f"Ошибка: {e}"))
        threading.Thread(target=fetch, daemon=True).start()

class ChatApp(App):
    server_url = StringProperty("")
    admin_secret = StringProperty("")

    def build(self):
        self.server_url = get_server_url()
        sm = ScreenManager()
        sm.add_widget(SettingsScreen(name='settings'))
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(ContactListScreen(name='contacts'))
        sm.add_widget(ChatScreen(name='chat'))
        sm.add_widget(AdminScreen(name='admin'))
        sm.current = 'settings' if not self.server_url else 'login'
        return sm

if __name__ == '__main__':
    ChatApp().run()