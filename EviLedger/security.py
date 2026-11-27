import hashlib, os, uuid
from pathlib import Path
from cryptography.fernet import Fernet
STORAGE=Path("storage/encrypted")
STORAGE.mkdir(parents=True,exist_ok=True)
KEY_PATH=Path("data/demo_encryption.key")
KEY_PATH.parent.mkdir(exist_ok=True)
def _key():
    env=os.getenv("EVILEDGER_FERNET_KEY")
    if env: return env.encode()
    if not KEY_PATH.exists(): KEY_PATH.write_bytes(Fernet.generate_key()); os.chmod(KEY_PATH,0o600)
    return KEY_PATH.read_bytes()
def sha256_bytes(data): return hashlib.sha256(data).hexdigest()
def encrypt_file(data,filename):
    token=Fernet(_key()).encrypt(data)
    ref=f"{uuid.uuid4().hex}.enc"
    (STORAGE/ref).write_bytes(token)
    return str(STORAGE/ref)
def decrypt_file(ref):
    return Fernet(_key()).decrypt(Path(ref).read_bytes())
