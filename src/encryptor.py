import plistlib
from Crypto.Cipher import AES
from decryptor import (
    AES_BLOCK,
    BackupWorkspace,
    FileEntry,
    ZERO_IV,
    ensure_dir,
    open_manifest_conn)

def pkcs7_pad(data: bytes, block_size: int = AES_BLOCK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def encrypt_cbc(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=ZERO_IV)
    return cipher.encrypt(pkcs7_pad(data))

def reencrypt_manifest_db(workspace: BackupWorkspace) -> None:
    assert workspace.backup_root is not None
    assert workspace.decrypted_manifest_db_path is not None
    assert workspace.manifest_aes_key is not None

    data = workspace.decrypted_manifest_db_path.read_bytes()
    (workspace.backup_root / "Manifest.db").write_bytes(encrypt_cbc(data, workspace.manifest_aes_key))

def write_entry_back(workspace: BackupWorkspace, entry: FileEntry) -> None:
    assert workspace.backup_root is not None

    if entry.flags != 1 or entry.meta.get("encryption_key") is None:
        return

    workspace_path = workspace.workspace_path_for_entry(entry)
    if not workspace_path.exists():
        raise FileNotFoundError(f"Workspace file missing: {workspace_path}")

    file_key = workspace._file_key_for_entry(entry)
    if file_key is None:
        return

    new_plain = workspace_path.read_bytes()
    encrypted = encrypt_cbc(new_plain, file_key)
    target = workspace.backup_root / entry.file_id[:2] / entry.file_id
    ensure_dir(target.parent)
    target.write_bytes(encrypted)

    if workspace.decrypted_manifest_db_path is None:
        return

    conn = open_manifest_conn(workspace.decrypted_manifest_db_path)
    cur = conn.cursor()
    cur.execute("SELECT file FROM Files WHERE fileID = ?", (entry.file_id,))
    row = cur.fetchone()
    if row is None:
        conn.close()
        raise KeyError(f"FileID not found in Manifest.db: {entry.file_id}")

    old_bplist = row["file"]
    try:
        plist = plistlib.loads(old_bplist)
        objects = plist["$objects"]
        root = objects[plist["$top"]["root"].data]
        old_size = int(root.get("Size", 0))
        new_size = len(new_plain)
        if old_size != new_size:
            root["Size"] = new_size
            new_bplist = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY)
            cur.execute("UPDATE Files SET file = ? WHERE fileID = ?", (new_bplist, entry.file_id))
            conn.commit()
    finally:
        conn.close()
