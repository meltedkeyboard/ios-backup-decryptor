# iOS Backup Decryptor

Python CLI utility for decrypting encrypted iTunes / Finder local iOS backups, extracting files, modifying backup contents, and writing encrypted data back into the original backup structure.

## Features

* Unlock encrypted iOS backups using the backup password
* Decrypt `Manifest.db`
* Enumerate backup entries
* Extract individual files
* Decrypt the entire backup into a workspace directory
* Modify extracted files and write them back encrypted
* Re-encrypt and commit `Manifest.db`
* Works directly with native iTunes / Finder backup format

---

## How to Install

1. Clone repo
2. (on Linux) create virtual env
3. Install requirements:

```bash
pip install -r requirements.txt
```

## Usage

General syntax:

```bash
python ./src/main.py --backup <BACKUP_PATH> --password <PASSWORD> COMMAND
```

Example:

```bash
python ./src/main.py \
  --backup ~/Library/Application\ Support/MobileSync/Backup/<DEVICE_ID> \
  --password mypassword \
  unlock
```

## Commands

### unlock

Verify the password and decrypt `Manifest.db`.

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  unlock
```

### decrypt

Decrypt all files from the backup into the workspace directory.

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  decrypt
```

Default workspace:

```text
~/ios_backup_working_directory
```

Custom workspace:

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  --workspace ./workspace \
  decrypt
```

### list

List entries stored in the backup.

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  list
```

Filter by domain:

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  list --domain HomeDomain
```

Filter by relative path:

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  list --filter sms
```

### extract

Extract a single file using a fileID prefix or exact relative path.

By fileID:

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  extract 3d0d7e5f
```

By relative path:

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  extract Library/SMS/sms.db
```

### write-back

Re-encrypt a modified workspace file and write it back into the original backup.

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  write-back Library/SMS/sms.db
```

How to edit a file algorythm:

1. Extract file
2. Modify/replace file inside workspace
3. Run `write-back`
4. Run `commit`

### commit

Re-encrypt and replace `Manifest.db` inside the backup.

```bash
python ./src/main.py \
  --backup <BACKUP_PATH> \
  --password <PASSWORD> \
  commit
```

## Notes

* The tool operates directly on backup files
* Always keep a separate untouched copy of the original backup.
* Some entries may not be regular files (`flags != 1`)
* Certain protected or unsupported entries may fail to decrypt
* Use rewriting ability of this project with caution

---

## Disclaimer

This project is provided for educational, research, interoperability, forensic, and personal backup analysis purposes only.

You are solely responsible for complying with all applicable laws and regulations in your jurisdiction.

Do not use this software on devices or backups that you do not own or have explicit authorization to analyze.
