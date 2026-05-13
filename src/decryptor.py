import os, re, sqlite3, struct, sys, plistlib
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from Crypto.Cipher import AES

WRAP_PASSPHRASE = 2
AES_BLOCK = 16
ZERO_IV = b"\x00" * 16

def parse_tlv(blob: bytes) -> List[Tuple[bytes, bytes]]:
    out: List[Tuple[bytes, bytes]] = []
    i = 0
    n = len(blob)
    while i + 8 <= n:
        tag = blob[i : i + 4]
        length = struct.unpack(">I", blob[i + 4 : i + 8])[0]
        value = blob[i + 8 : i + 8 + length]
        out.append((tag, value))
        i += 8 + length
    return out

def _maybe_int(tag: bytes, value: bytes) -> Any:
    if tag in {b"TYPE", b"WRAP", b"CLAS", b"KTYP", b"PBKY", b"DPIC", b"ITER"} and len(value) == 4:
        return struct.unpack(">I", value)[0]
    return value

def parse_keybag(blob: bytes) -> Tuple[Dict[bytes, Any], Dict[int, Dict[bytes, Any]]]:
    attrs: Dict[bytes, Any] = {}
    class_keys: Dict[int, Dict[bytes, Any]] = {}
    current_ck: Optional[Dict[bytes, Any]] = None

    for tag, value in parse_tlv(blob):
        ivalue = _maybe_int(tag, value)
        if tag == b"UUID" and b"UUID" not in attrs:
            attrs[b"UUID"] = value
            continue
        if tag == b"UUID":
            if current_ck and b"CLAS" in current_ck:
                class_keys[int(current_ck[b"CLAS"])] = current_ck
            current_ck = {b"UUID": value}
            continue

        if tag in (b"CLAS", b"WRAP", b"KTYP", b"PBKY", b"WPKY"):
            if current_ck is not None:
                current_ck[tag] = ivalue
            else:
                attrs[tag] = ivalue
        else:
            attrs[tag] = ivalue

    if current_ck and b"CLAS" in current_ck:
        class_keys[int(current_ck[b"CLAS"])] = current_ck
    return attrs, class_keys


def derive_passphrase_key(password: str, attrs: Dict[bytes, Any]) -> bytes:
    salt256 = attrs.get(b"DPSL")
    salt1 = attrs.get(b"SALT")
    iter256 = attrs.get(b"DPIC")
    iter1 = attrs.get(b"ITER")

    if not isinstance(salt256, (bytes, bytearray)) or not isinstance(salt1, (bytes, bytearray)):
        raise ValueError("Backup keybag is missing PBKDF2 salts.")
    if not isinstance(iter256, int) or not isinstance(iter1, int):
        raise ValueError("Backup keybag is missing PBKDF2 iteration counts.")

    round1 = pbkdf2_hmac("sha256", password.encode("utf-8"), bytes(salt256), int(iter256), dklen=32)
    return pbkdf2_hmac("sha1", round1, bytes(salt1), int(iter1), dklen=32)


def aes_unwrap(kek: bytes, wrapped: bytes) -> Optional[bytes]:
    if len(wrapped) < 16 or len(wrapped) % 8 != 0:
        return None

    n = len(wrapped) // 8 - 1
    blocks = [int.from_bytes(wrapped[i * 8 : (i + 1) * 8], "big") for i in range(len(wrapped) // 8)]
    a = blocks[0]
    r = [0] + blocks[1:]

    cipher = AES.new(kek, AES.MODE_ECB)
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (n * j) + i
            b = cipher.decrypt(((a ^ t).to_bytes(8, "big") + r[i].to_bytes(8, "big")))
            a = int.from_bytes(b[:8], "big")
            r[i] = int.from_bytes(b[8:], "big")

    if a != 0xA6A6A6A6A6A6A6A6:
        return None
    return b"".join(x.to_bytes(8, "big") for x in r[1:])


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 input length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Corrupt PKCS#7 padding.")
    return data[:-pad_len]


def decrypt_cbc(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=ZERO_IV)
    return pkcs7_unpad(cipher.decrypt(data))


def load_manifest_plist(backup_root: Path) -> Dict[str, Any]:
    with open(backup_root / "Manifest.plist", "rb") as f:
        manifest = plistlib.load(f)
    if manifest.get("IsEncrypted") is not True:
        raise ValueError("This backup is not marked as encrypted.")
    return manifest


def unwrap_class_keys(
    class_keys: Dict[int, Dict[bytes, Any]],
    passphrase_key: bytes,
) -> Dict[int, bytes]:
    unlocked: Dict[int, bytes] = {}
    for class_id, ck in class_keys.items():
        wrapped = ck.get(b"WPKY")
        wrap_flags = ck.get(b"WRAP", 0)
        if isinstance(wrapped, (bytes, bytearray)) and int(wrap_flags) & WRAP_PASSPHRASE:
            key = aes_unwrap(passphrase_key, bytes(wrapped))
            if key is None:
                raise ValueError("Wrong password or damaged keybag.")
            unlocked[int(class_id)] = key
    if not unlocked:
        raise ValueError("No passphrase-wrapped class keys were unlocked.")
    return unlocked


def unwrap_manifest_key(manifest_plist: Dict[str, Any], unlocked_class_keys: Dict[int, bytes]) -> bytes:
    manifest_key_raw = manifest_plist["ManifestKey"]
    if not isinstance(manifest_key_raw, (bytes, bytearray)) or len(manifest_key_raw) != 44:
        raise ValueError("Unexpected ManifestKey format.")
    class_id = struct.unpack("<I", manifest_key_raw[:4])[0]
    wrapped = manifest_key_raw[4:]
    class_key = unlocked_class_keys.get(class_id)
    if class_key is None:
        raise ValueError(f"Missing unlocked class key for class {class_id}.")
    manifest_aes_key = aes_unwrap(class_key, wrapped)
    if manifest_aes_key is None:
        raise ValueError("Failed to unwrap Manifest.db key.")
    return manifest_aes_key

def decrypt_manifest_db(backup_root: Path, manifest_aes_key: bytes, workspace: Path) -> Path:
    enc_path = backup_root / "Manifest.db"
    plain_path = workspace / "Manifest.db"
    data = enc_path.read_bytes()
    cipher = AES.new(manifest_aes_key, AES.MODE_CBC, iv=ZERO_IV)
    plain_path.write_bytes(pkcs7_unpad(cipher.decrypt(data)))
    return plain_path

def open_manifest_conn(manifest_db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(manifest_db_path))
    conn.row_factory = sqlite3.Row
    return conn

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def domain_safe_name(domain: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", domain)

def parse_file_bplist(blob: bytes) -> Dict[str, Any]:
    plist = plistlib.loads(blob)
    objects = plist["$objects"]
    root = objects[plist["$top"]["root"].data]
    result = {
        "mtime": root.get("LastModified"),
        "birth": root.get("Birth"),
        "size": int(root.get("Size", 0)),
        "protection_class": int(root.get("ProtectionClass", 0)),
        "mode": root.get("Mode"),
        "inode": root.get("InodeNumber"),
        "encryption_key": None,
    }
    if "EncryptionKey" in root:
        enc_key_obj = objects[root["EncryptionKey"].data]
        ns_data = enc_key_obj["NS.data"]
        result["encryption_key"] = ns_data[4:]
    return result

@dataclass
class FileEntry:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    meta: Dict[str, Any]
    file_bplist: bytes

class BackupWorkspace:
    def __init__(self) -> None:
        self.backup_root: Optional[Path] = None
        self.workspace_root: Optional[Path] = None
        self.manifest_plist: Optional[Dict[str, Any]] = None
        self.attrs: Optional[Dict[bytes, Any]] = None
        self.class_keys: Dict[int, Dict[bytes, Any]] = {}
        self.unlocked_class_keys: Dict[int, bytes] = {}
        self.manifest_aes_key: Optional[bytes] = None
        self.manifest_db_path: Optional[Path] = None
        self.decrypted_manifest_db_path: Optional[Path] = None
        self.entries: List[FileEntry] = []

    def open(self, backup_root: Path, password: str, workspace_root: Path) -> None:
        self.backup_root = backup_root
        self.workspace_root = workspace_root
        ensure_dir(workspace_root)

        self.manifest_plist = load_manifest_plist(backup_root)
        keybag_blob = self.manifest_plist["BackupKeyBag"]
        attrs, class_keys = parse_keybag(keybag_blob)
        self.attrs = attrs
        self.class_keys = class_keys
        passphrase_key = derive_passphrase_key(password, attrs)
        self.unlocked_class_keys = unwrap_class_keys(class_keys, passphrase_key)
        self.manifest_aes_key = unwrap_manifest_key(self.manifest_plist, self.unlocked_class_keys)
        self.manifest_db_path = backup_root / "Manifest.db"
        self.decrypted_manifest_db_path = decrypt_manifest_db(backup_root, self.manifest_aes_key, workspace_root)
        self.entries = self.load_entries()

    def load_entries(self) -> List[FileEntry]:
        if self.decrypted_manifest_db_path is None:
            return []
        conn = open_manifest_conn(self.decrypted_manifest_db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT fileID, domain, relativePath, flags, file FROM Files ORDER BY domain, relativePath"
        )
        entries: List[FileEntry] = []
        for row in cur.fetchall():
            meta: Dict[str, Any] = {}
            file_bplist = row["file"]
            if file_bplist:
                try:
                    meta = parse_file_bplist(file_bplist)
                except Exception:
                    meta = {}
            entries.append(
                FileEntry(
                    file_id=row["fileID"],
                    domain=row["domain"],
                    relative_path=row["relativePath"] or "",
                    flags=int(row["flags"]),
                    meta=meta,
                    file_bplist=file_bplist,
                )
            )
        conn.close()
        return entries

    def workspace_plain_root(self) -> Path:
        assert self.workspace_root is not None
        return self.workspace_root / "plaintext"

    def _file_key_for_entry(self, entry: FileEntry) -> Optional[bytes]:
        enc_key = entry.meta.get("encryption_key")
        prot_class = entry.meta.get("protection_class")
        if enc_key is None:
            return None
        if prot_class not in self.unlocked_class_keys:
            raise ValueError(f"Missing class key for protection class {prot_class}.")
        file_key = aes_unwrap(self.unlocked_class_keys[int(prot_class)], enc_key)
        if file_key is None:
            raise ValueError(f"Failed to unwrap file key for {entry.file_id}.")
        return file_key

    def workspace_path_for_entry(self, entry: FileEntry) -> Path:
        return self.workspace_plain_root() / domain_safe_name(entry.domain) / entry.relative_path

    def decrypt_entry_to_workspace(self, entry: FileEntry) -> Optional[Path]:
        assert self.backup_root is not None

        if entry.flags == 2:
            target = self.workspace_path_for_entry(entry)
            ensure_dir(target)
            return target

        if entry.flags != 1:
            return None

        target = self.workspace_path_for_entry(entry)

        if entry.meta.get("encryption_key") is None:
            ensure_dir(target.parent)
            target.touch(exist_ok=True)
            return target

        file_key = self._file_key_for_entry(entry)
        if file_key is None:
            return None

        enc_path = self.backup_root / entry.file_id[:2] / entry.file_id
        encrypted = enc_path.read_bytes()
        plain = decrypt_cbc(encrypted, file_key)
        ensure_dir(target.parent)
        target.write_bytes(plain)
        return target

    def decrypt_all_to_workspace(self) -> int:
        count = 0
        for entry in self.entries:
            try:
                out = self.decrypt_entry_to_workspace(entry)
                if out is not None:
                    count += 1
            except Exception:
                continue
        return count

    def open_workspace_in_file_manager(self) -> None:
        root = self.workspace_plain_root()
        ensure_dir(root)
        open_in_file_manager(root)

    def refresh_entries(self) -> None:
        self.entries = self.load_entries()


def open_path_default(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        os.system(f'open "{path}"')
    else:
        os.system(f'xdg-open "{path}"')

def open_in_file_manager(path: Path, select_item: bool = True) -> None:
    if sys.platform.startswith("win"):
        if select_item and path.is_file():
            os.system(f'explorer /select,"{path}"')
        else:
            os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        if select_item and path.is_file():
            os.system(f'open -R "{path}"')
        else:
            os.system(f'open "{path}"')
    else:
        if path.is_file():
            os.system(f'xdg-open "{path.parent}"')
        else:
            os.system(f'xdg-open "{path}"')
