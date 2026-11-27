# EviLedger — Secure Digital Evidence Provenance

EviLedger is a local academic prototype for case evidence registration, encrypted file storage, custody tracking, integrity verification, court reports, and a local hash-ledger audit simulation. All built-in records are synthetic.

## macOS setup

```bash
cd EviLedger

python3 -m venv .venv

source .venv/bin/activate

python -m pip install --upgrade pip

python -m pip install -r requirements.txt

python -m streamlit run app.py
```

The application opens at http://localhost:8501.

On the first run, initialize the SQLite database and create the first administrator account from another Terminal in the project directory:

```bash
source .venv/bin/activate
python database.py create-admin
```

Enter a unique badge number and a password of at least 12 characters when prompted. The password is stored as a salted PBKDF2-HMAC-SHA256 hash. Do not use a real operational password. Then sign in through the application.

## Features

- Cases, officers, evidence acquisition, SHA-256 fingerprints, Fernet encrypted evidence files, transfers, access history, court submissions, and PDF integrity summaries.
- SQLite foreign key enforcement, unique keys, normalized role and permission catalogs, parameterized lookups, indexes, reusable views, and audit triggers.
- Custody transfers use `BEGIN IMMEDIATE`; event records and pending/anchored local ledger records are in the same database transaction.
- Custody event hashes are SHA-256 over canonical event fields and the previous event hash. The DBMS CONTROL CENTER includes chain checks, database integrity checks, schema inspection, query plans, analytics, backups, and recovery.
- Role-based navigation is permission checked after login. The permission matrix is also shown in the control center.

## DBMS design notes

`schema.sql` documents the relational structure. Case, officer, evidence, custody, access, submission, role, permission, and anchor relationships use primary and foreign keys. The control center displays SQLite table metadata and relationships. Several original workflow attributes (such as evidence type, role name, department, and court name) remain stored as descriptive text for compatibility with the supplied database and workflow; corresponding lookup catalogs are present for the normalized design demonstration. A fully migrated lookup-ID schema for existing databases is not yet performed automatically.

The custody ledger is a local SQLite simulation. It is not decentralized and is not a production blockchain. SQLite and local backups do not provide tamper-resistant off-device durability. Fernet key management is local and is not a production key-management service. The PDF is an academic summary, not a statutory certificate. Do not store real confidential evidence in this prototype.

## Tests

Install requirements, then run:

```bash
python -m unittest discover -s tests -v
```

The tests use temporary databases and synthetic bytes to cover constraints, permissions, custody chain construction, transfer, hash immutability, password verification, and backup/restore.

## Project files

- `app.py` — Streamlit UI and workflows
- `database.py` — schema initialization, queries, transactions, auth, and backups
- `schema.sql` — SQL design reference
- `security.py` — SHA-256 and Fernet encrypted file storage
- `ledger.py` — local ledger simulation
- `reports.py` — PDF report generation
- `tests/` — synthetic database tests
- `data/` and `storage/` — local runtime data; excluded from the distributable ZIP
