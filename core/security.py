import os
import pyotp
import logging
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from core.config import Config

log = logging.getLogger("winhub.security")

class SecurityManager:
    def __init__(self, service_name=Config.SERVICE_NAME):
        self.service_name = service_name
        self.cipher = self._init_cipher()
        self.master_cipher = self._init_master_cipher()

    def _init_cipher(self):
        """Отримує ключ для TOTP та системних секретів з оточення або файлу"""
        try:
            sys_key = os.environ.get("WINHUB_SYS_SECRET")
            if not sys_key:
                # Зберігаємо ключ у захищеному файлі замість нестабільного keyring
                key_path = os.path.join(Config.DATA_DIR, 'sys_secret.enc')
                if os.path.exists(key_path):
                    with open(key_path, 'r', encoding='utf-8') as f:
                        sys_key = f.read().strip()
                else:
                    sys_key = Fernet.generate_key().decode()
                    os.makedirs(Config.DATA_DIR, exist_ok=True)
                    if self._write_private_key(key_path, sys_key):
                        log.warning(f"Згенеровано новий Sys Secret. Збережено в {key_path}")
                    else:
                        with open(key_path, 'r', encoding='utf-8') as f:
                            sys_key = f.read().strip()
                self._lock_private_key(key_path)
            return Fernet(sys_key.encode())
        except Exception as e:
            log.error(f"Error init sys cipher: {e}")
            return None

    def _init_master_cipher(self):
        """Отримує Глобальний Master Key для шифрування Payload та Логів агентів"""
        try:
            master_key = os.environ.get("WINHUB_MASTER_KEY")
            if not master_key:
                key_path = os.path.join(Config.DATA_DIR, 'master_key.enc')
                if os.path.exists(key_path):
                    with open(key_path, 'r', encoding='utf-8') as f:
                        master_key = f.read().strip()
                else:
                    master_key = Fernet.generate_key().decode()
                    os.makedirs(Config.DATA_DIR, exist_ok=True)
                    if self._write_private_key(key_path, master_key):
                        log.warning(f"Згенеровано новий Master Key. Збережено в {key_path}")
                    else:
                        with open(key_path, 'r', encoding='utf-8') as f:
                            master_key = f.read().strip()
                self._lock_private_key(key_path)
            return Fernet(master_key.encode())
        except Exception as e:
            log.error(f"Error init master cipher: {e}")
            return None

    @staticmethod
    def _lock_private_key(path):
        if os.path.islink(path):
            raise RuntimeError(f"Secret key path must not be a symbolic link: {path}")
        if os.name != 'nt':
            os.chmod(path, 0o600)

    @staticmethod
    def _write_private_key(path, value):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(descriptor, 'w', encoding='utf-8') as key_file:
            key_file.write(value)
            key_file.flush()
            os.fsync(key_file.fileno())
        return True

    # --- TOTP / SYSTEM SECRETS ---
    def encrypt_data(self, data: str) -> str:
        if not self.cipher or not data: return ""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        if not self.cipher or not encrypted_data: return ""
        try: return self.cipher.decrypt(encrypted_data.encode()).decode()
        except: return ""

    # --- GLOBAL PAYLOAD ENCRYPTION ---
    def encrypt_payload(self, data: str) -> str:
        if not self.master_cipher or not data: return ""
        return self.master_cipher.encrypt(data.encode('utf-8')).decode('utf-8')

    def decrypt_payload(self, encrypted_data: str) -> str:
        if not self.master_cipher or not encrypted_data: return ""
        try: return self.master_cipher.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
        except: return "[Decryption Failed]"

    # --- PASSWORDS ---
    @staticmethod
    def hash_password(password: str) -> str:
        return generate_password_hash(password)

    @staticmethod
    def verify_password(p_hash: str, password: str) -> bool:
        return check_password_hash(p_hash, password)

    @staticmethod
    def generate_totp_secret() -> str:
        return pyotp.random_base32()

sec_manager = SecurityManager()
