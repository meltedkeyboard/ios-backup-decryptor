import argparse, sys, traceback
from pathlib import Path
from decryptor import BackupWorkspace, FileEntry
from encryptor import reencrypt_manifest_db, write_entry_back
from utils import ProgressBar, log_fail, log_info, log_ok, log_warn

DEFAULT_WORKSPACE = Path.home() / "ios_backup_working_directory"

def open_workspace(args: argparse.Namespace) -> BackupWorkspace:
    backup = Path(args.backup)
    workspace = Path(args.workspace)
    password: str = args.password

    if not backup.is_dir():
        log_fail(f"Backup folder not found: {backup}")
        sys.exit(1)

    log_info(f"Backup: {backup}")
    log_info(f"Workspace: {workspace}")
    log_info("Derviation of passphrase key...")

    ws = BackupWorkspace()
    ws.open(backup, password, workspace)

    log_ok(f"Keybag unlocked -- {len(ws.unlocked_class_keys)} class keys, {len(ws.entries)} entries")
    return ws

def cmd_unlock(args: argparse.Namespace) -> None:
    open_workspace(args)


def cmd_decrypt(args: argparse.Namespace) -> None:
    ws = open_workspace(args)

    total = len(ws.entries)
    log_info(f"Decryption of {total} entries to workspace...")

    bar = ProgressBar(total=total, label="decrypting")
    ok_count = 0
    skip_count = 0
    fail_count = 0

    for entry in ws.entries:
        try:
            out = ws.decrypt_entry_to_workspace(entry)
            if out is not None:
                ok_count += 1
            else:
                skip_count += 1
        except Exception as exc:
            fail_count += 1
            log_warn(f"Skipped {entry.file_id[:8]}... ({entry.domain}/{entry.relative_path}): {exc}")
        bar.advance()

    bar.finish()

    if fail_count:
        log_warn(f"{fail_count} entries failed (see warnings above)")
    log_ok(f"Decrypted {ok_count} files, skipped {skip_count}, failed {fail_count}")
    log_info(f"Output: {ws.workspace_plain_root()}")

def cmd_list(args: argparse.Namespace) -> None:
    ws = open_workspace(args)

    domain_filter: str = (args.domain or "").strip().lower()
    path_filter: str = (args.filter or "").strip().lower()

    entries = ws.entries
    if domain_filter:
        entries = [e for e in entries if domain_filter in e.domain.lower()]
    if path_filter:
        entries = [e for e in entries if path_filter in e.relative_path.lower()]

    if not entries:
        log_warn("No entries match the given filters.")
        return

    log_info(f"Showing {len(entries)} of {len(ws.entries)} entries:\n")

    col_id     = 10
    col_domain = 44
    col_flags  = 6
    col_size   = 10

    header = (
        f"{'FILE_ID':<{col_id}}  "
        f"{'DOMAIN':<{col_domain}}  "
        f"{'FLAGS':<{col_flags}}  "
        f"{'SIZE':>{col_size}}  "
        f"RELATIVE_PATH"
    )
    print(header)
    print("-" * (len(header) + 20))

    for e in entries:
        size = e.meta.get("size", "")
        size_str = f"{size:,}" if isinstance(size, int) else str(size or "-")
        print(
            f"{e.file_id[:8]:<{col_id}}  "
            f"{e.domain[:col_domain]:<{col_domain}}  "
            f"{e.flags:<{col_flags}}  "
            f"{size_str:>{col_size}}  "
            f"{e.relative_path}"
        )

    print()
    log_info(f"Total: {len(entries)} entries")

def find_entry(ws: BackupWorkspace, selector: str) -> FileEntry:
    by_id = [e for e in ws.entries if e.file_id.startswith(selector)]
    if len(by_id) == 1:
        return by_id[0]
    if len(by_id) > 1:
        log_fail(f"Ambiguous fileID prefix '{selector}' matches {len(by_id)} entries. Use more characters.")
        sys.exit(1)

    by_path = [e for e in ws.entries if e.relative_path == selector]
    if len(by_path) == 1:
        return by_path[0]
    if len(by_path) > 1:
        log_warn(f"Path '{selector}' appears in {len(by_path)} domains. Picking the first match.")
        log_warn("Use --file-id for an unambiguous selection.")
        return by_path[0]

    log_fail(f"No entry found for selector: {selector}")
    sys.exit(1)

def cmd_extract(args: argparse.Namespace) -> None:
    ws = open_workspace(args)

    selector: str = args.selector
    log_info(f"Resolving entry: {selector}")
    entry = find_entry(ws, selector)

    log_info(f"Entry:  {entry.domain} / {entry.relative_path}")
    log_info(f"FileID: {entry.file_id}")
    log_info(f"Flags:  {entry.flags}  |  Protection class: {entry.meta.get('protection_class')}")
    log_info(f"Size:   {entry.meta.get('size', 'unknown')} bytes")

    if entry.flags != 1:
        log_warn("Selected entry is not a regular file (flags != 1). Nothing to extract.")
        return

    out_path = ws.decrypt_entry_to_workspace(entry)
    if out_path is None:
        log_fail("Decryption returned no output. Entry may have no encryption key or unsupported flags.")
        sys.exit(1)

    log_ok(f"Extracted to: {out_path}")

def cmd_write_back(args: argparse.Namespace) -> None:
    ws = open_workspace(args)

    selector: str = args.selector
    log_info(f"Resolving entry: {selector}")
    entry = find_entry(ws, selector)

    log_info(f"Entry:     {entry.domain} / {entry.relative_path}")
    log_info(f"FileID:    {entry.file_id}")

    workspace_path = ws.workspace_path_for_entry(entry)
    if not workspace_path.exists():
        log_fail(f"Workspace copy not found: {workspace_path}")
        log_fail("Run 'extract' first, edit the file, then run 'write-back'.")
        sys.exit(1)

    log_info(f"Source:    {workspace_path}")
    log_info("Re-encrypting and writing back into backup...")

    write_entry_back(ws, entry)
    log_ok(f"Written back: {ws.backup_root / entry.file_id[:2] / entry.file_id}")


def cmd_commit(args: argparse.Namespace) -> None:
    ws = open_workspace(args)

    if ws.decrypted_manifest_db_path is None or not ws.decrypted_manifest_db_path.exists():
        log_fail("Decrypted Manifest.db not found in workspace. Run 'unlock' first.")
        sys.exit(1)

    log_info(f"Source:  {ws.decrypted_manifest_db_path}")
    log_info(f"Target:  {ws.backup_root / 'Manifest.db'}")
    log_info("Re-encrypting Manifest.db...")

    reencrypt_manifest_db(ws)
    log_ok("Manifest.db committed back to backup.")

def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="ios-backup-decryptor",
        description="iOS Backup Decryptor\nCLI for encrypted backup decryption and write-back.",
        epilog="GitHub: https://github.com/meltedkeyboard/ios-backup-decryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    root.add_argument("--backup", required=True, metavar="PATH", help="Path to the iOS backup folder")
    root.add_argument("--password", required=True, metavar="PWD", help="Backup encryption password")
    root.add_argument("--workspace", default=str(DEFAULT_WORKSPACE), metavar="PATH", help=f"Workspace output folder (default: {DEFAULT_WORKSPACE})")

    sub = root.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    sub.add_parser("unlock", help="Verify password and decrypt Manifest.db")
    sub.add_parser("decrypt", help="Decrypt all files into the workspace directory")

    p_list = sub.add_parser("list", help="List backup entries")
    p_list.add_argument("--domain", metavar="DOMAIN", help="Filter by domain substring (case-insensitive)")
    p_list.add_argument("--filter", metavar="SUBSTR", help="Filter by relative path substring (case-insensitive)")

    p_extract = sub.add_parser("extract", help="Extract a single file by fileID prefix or relative path")
    p_extract.add_argument("selector", metavar="FILE_ID_OR_PATH", help="fileID prefix (>=8 chars) or exact relative path")

    p_wb = sub.add_parser("write-back", help="Re-encrypt a modified workspace file back into the backup")
    p_wb.add_argument("selector", metavar="FILE_ID_OR_PATH", help="fileID prefix (>=8 chars) or exact relative path")

    sub.add_parser("commit", help="Re-encrypt the modified Manifest.db back into the backup")
    return root

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "unlock": cmd_unlock,
        "decrypt": cmd_decrypt,
        "list": cmd_list,
        "extract": cmd_extract,
        "write-back": cmd_write_back,
        "commit": cmd_commit,
    }

    try:
        dispatch[args.command](args)
    except KeyboardInterrupt:
        print()
        log_warn("Interrupted by user.")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:
        log_fail(f"{type(exc).__name__}: {exc}")
        if "--debug" in sys.argv:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
