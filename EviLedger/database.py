import sqlite3, json, hashlib, uuid
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager, closing
from security import encrypt_file, decrypt_file, sha256_bytes, STORAGE

DB=Path("data/eviledger.db")
BACKUP_DIR=Path("backups")
DB.parent.mkdir(exist_ok=True)
def now(): return datetime.now(timezone.utc).isoformat()
@contextmanager
def get_conn():
    c=sqlite3.connect(DB, timeout=20)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
def init_db():
    with get_conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS cases(case_id INTEGER PRIMARY KEY,case_number TEXT UNIQUE NOT NULL,case_type TEXT,title TEXT,jurisdiction TEXT,description TEXT,status TEXT DEFAULT 'Open',opened_at TEXT);
        CREATE TABLE IF NOT EXISTS officers(officer_id INTEGER PRIMARY KEY,name TEXT NOT NULL,badge_number TEXT UNIQUE NOT NULL,role TEXT NOT NULL,department TEXT,email TEXT,status TEXT DEFAULT 'Active');
        CREATE TABLE IF NOT EXISTS evidence(evidence_id INTEGER PRIMARY KEY,case_id INTEGER NOT NULL REFERENCES cases, evidence_type TEXT,description TEXT,source TEXT,original_hash TEXT,hash_algorithm TEXT DEFAULT 'SHA-256',encrypted_object_ref TEXT,status TEXT DEFAULT 'Seized',created_at TEXT,current_custodian_id INTEGER REFERENCES officers,filename TEXT);
        CREATE TABLE IF NOT EXISTS custody_events(event_id INTEGER PRIMARY KEY,evidence_id INTEGER NOT NULL REFERENCES evidence,from_officer_id INTEGER REFERENCES officers,to_officer_id INTEGER NOT NULL REFERENCES officers,event_type TEXT,event_time TEXT,location TEXT,purpose TEXT,event_hash TEXT,blockchain_status TEXT DEFAULT 'Pending',digital_signature TEXT);
        CREATE TABLE IF NOT EXISTS access_logs(access_id INTEGER PRIMARY KEY,evidence_id INTEGER REFERENCES evidence,officer_id INTEGER REFERENCES officers,access_type TEXT,access_time TEXT,device_id TEXT,result TEXT,reason TEXT);
        CREATE TABLE IF NOT EXISTS court_submissions(submission_id INTEGER PRIMARY KEY,evidence_id INTEGER REFERENCES evidence,court_name TEXT,submitted_by INTEGER REFERENCES officers,submission_time TEXT,verification_result TEXT);
        CREATE TABLE IF NOT EXISTS blockchain_anchors(anchor_id INTEGER PRIMARY KEY,record_type TEXT,record_id TEXT,record_hash TEXT,transaction_id TEXT UNIQUE,anchored_at TEXT,status TEXT);
        CREATE TABLE IF NOT EXISTS roles(role_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS departments(department_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence_types(evidence_type_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS event_types(event_type_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS permissions(permission_id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, description TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS role_permissions(role_id INTEGER NOT NULL REFERENCES roles, permission_id INTEGER NOT NULL REFERENCES permissions, PRIMARY KEY(role_id,permission_id));
        CREATE TABLE IF NOT EXISTS courts(court_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS officer_auth(officer_id INTEGER PRIMARY KEY REFERENCES officers ON DELETE CASCADE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transaction_log(transaction_id INTEGER PRIMARY KEY, operation TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('SUCCESS','FAILURE')), details TEXT, recorded_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS backup_history(backup_id INTEGER PRIMARY KEY, path TEXT NOT NULL, created_at TEXT NOT NULL, integrity_result TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(original_hash);
        CREATE INDEX IF NOT EXISTS idx_events_officer ON custody_events(to_officer_id,event_time);
        CREATE INDEX IF NOT EXISTS idx_events_evidence ON custody_events(evidence_id,event_time);
        CREATE INDEX IF NOT EXISTS idx_access_evidence ON access_logs(evidence_id,access_time);
        CREATE INDEX IF NOT EXISTS idx_access_officer ON access_logs(officer_id,access_time);
        CREATE VIEW IF NOT EXISTS evidence_details AS SELECT e.*,c.case_number,o.name AS custodian_name FROM evidence e JOIN cases c USING(case_id) LEFT JOIN officers o ON o.officer_id=e.current_custodian_id;
        CREATE VIEW IF NOT EXISTS custody_history_view AS SELECT ce.*,f.name AS from_officer,t.name AS to_officer FROM custody_events ce LEFT JOIN officers f ON f.officer_id=ce.from_officer_id JOIN officers t ON t.officer_id=ce.to_officer_id;
        CREATE VIEW IF NOT EXISTS officer_activity_view AS SELECT o.officer_id,o.name,COUNT(a.access_id) AS access_count FROM officers o LEFT JOIN access_logs a USING(officer_id) GROUP BY o.officer_id,o.name;
        CREATE VIEW IF NOT EXISTS court_submission_view AS SELECT s.*,e.case_id,c.case_number FROM court_submissions s JOIN evidence e USING(evidence_id) JOIN cases c USING(case_id);
        CREATE VIEW IF NOT EXISTS integrity_status_view AS SELECT e.evidence_id,e.original_hash,COUNT(a.anchor_id) AS anchor_count FROM evidence e LEFT JOIN blockchain_anchors a ON a.record_type='evidence' AND a.record_id=CAST(e.evidence_id AS TEXT) GROUP BY e.evidence_id;
        CREATE TRIGGER IF NOT EXISTS evidence_hash_immutable BEFORE UPDATE OF original_hash ON evidence WHEN OLD.original_hash IS NOT NEW.original_hash BEGIN SELECT RAISE(ABORT,'original evidence hash is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS custody_events_immutable_update BEFORE UPDATE ON custody_events WHEN OLD.evidence_id IS NOT NEW.evidence_id OR OLD.from_officer_id IS NOT NEW.from_officer_id OR OLD.to_officer_id IS NOT NEW.to_officer_id OR OLD.event_type IS NOT NEW.event_type OR OLD.event_time IS NOT NEW.event_time OR OLD.location IS NOT NEW.location OR OLD.purpose IS NOT NEW.purpose OR OLD.event_hash IS NOT NEW.event_hash BEGIN SELECT RAISE(ABORT,'custody events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS custody_events_immutable_delete BEFORE DELETE ON custody_events BEGIN SELECT RAISE(ABORT,'custody events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS evidence_status_audit AFTER UPDATE OF status ON evidence WHEN OLD.status IS NOT NEW.status BEGIN INSERT INTO access_logs(evidence_id,access_type,access_time,result,reason) VALUES(NEW.evidence_id,'status-change',strftime('%Y-%m-%dT%H:%M:%fZ','now'),'Success',OLD.status||' -> '||NEW.status); END;
        CREATE TRIGGER IF NOT EXISTS evidence_status_valid_insert BEFORE INSERT ON evidence WHEN NEW.status NOT IN ('Seized','Transferred','Under Review','Submitted','Archived') BEGIN SELECT RAISE(ABORT,'invalid evidence status'); END;
        CREATE TRIGGER IF NOT EXISTS evidence_status_valid_update BEFORE UPDATE OF status ON evidence WHEN NEW.status NOT IN ('Seized','Transferred','Under Review','Submitted','Archived') BEGIN SELECT RAISE(ABORT,'invalid evidence status'); END;
        CREATE TRIGGER IF NOT EXISTS officer_role_valid_insert BEFORE INSERT ON officers WHEN NEW.role NOT IN ('Seizing Officer','Investigating Officer','Forensic Analyst','Storage Custodian','Court Officer','Auditor','Administrator') BEGIN SELECT RAISE(ABORT,'invalid officer role'); END;
        CREATE TRIGGER IF NOT EXISTS case_status_valid_insert BEFORE INSERT ON cases WHEN NEW.status NOT IN ('Open','Closed','On Hold') BEGIN SELECT RAISE(ABORT,'invalid case status'); END;
        CREATE TRIGGER IF NOT EXISTS case_status_valid_update BEFORE UPDATE OF status ON cases WHEN NEW.status NOT IN ('Open','Closed','On Hold') BEGIN SELECT RAISE(ABORT,'invalid case status'); END;
        CREATE TRIGGER IF NOT EXISTS officer_status_valid_insert BEFORE INSERT ON officers WHEN NEW.status NOT IN ('Active','Inactive') BEGIN SELECT RAISE(ABORT,'invalid officer status'); END;
        CREATE TRIGGER IF NOT EXISTS access_result_valid_insert BEFORE INSERT ON access_logs WHEN NEW.result NOT IN ('Success','Failed') BEGIN SELECT RAISE(ABORT,'invalid access result'); END;
        CREATE TRIGGER IF NOT EXISTS submission_result_valid_insert BEFORE INSERT ON court_submissions WHEN NEW.verification_result NOT IN ('Verified','Failed') BEGIN SELECT RAISE(ABORT,'invalid submission result'); END;
        CREATE TRIGGER IF NOT EXISTS custody_event_valid_insert BEFORE INSERT ON custody_events WHEN NEW.event_type NOT IN ('Seizure','Transfer') OR (NEW.event_type='Seizure' AND (NEW.from_officer_id IS NOT NULL OR NEW.to_officer_id != (SELECT current_custodian_id FROM evidence WHERE evidence_id=NEW.evidence_id))) OR (NEW.event_type='Transfer' AND (NEW.from_officer_id IS NULL OR NEW.from_officer_id != (SELECT current_custodian_id FROM evidence WHERE evidence_id=NEW.evidence_id))) BEGIN SELECT RAISE(ABORT,'invalid custody event'); END;
        """)
        # Seed normalized catalogs and an explicit permission matrix.
        roles = ["Seizing Officer","Investigating Officer","Forensic Analyst","Storage Custodian","Court Officer","Auditor","Administrator"]
        perms = [("case.view","View cases"),("evidence.acquire","Acquire evidence"),("evidence.view","View evidence"),("evidence.transfer","Transfer custody"),("evidence.verify","Verify integrity"),("court.manage","Manage court submissions"),("audit.view","View audit records"),("users.manage","Manage officers")]
        c.executemany("INSERT OR IGNORE INTO roles(name) VALUES(?)",[(x,) for x in roles])
        c.executemany("INSERT OR IGNORE INTO permissions(code,description) VALUES(?,?)",perms)
        matrix={"Seizing Officer":["evidence.acquire","evidence.view"],"Investigating Officer":["case.view","evidence.view","evidence.transfer"],"Forensic Analyst":["evidence.view","evidence.verify"],"Storage Custodian":["evidence.view","evidence.transfer"],"Court Officer":["evidence.view","court.manage"],"Auditor":["case.view","evidence.view","evidence.verify","audit.view"],"Administrator":[x[0] for x in perms]}
        for role,codes in matrix.items():
            for code in codes:
                c.execute("INSERT OR IGNORE INTO role_permissions SELECT r.role_id,p.permission_id FROM roles r,permissions p WHERE r.name=? AND p.code=?",(role,code))
        c.commit()
def create_case(number,typ,title,jurisdiction,description):
    with get_conn() as c:
        cur=c.execute("INSERT INTO cases(case_number,case_type,title,jurisdiction,description,opened_at) VALUES(?,?,?,?,?,?)",(number,typ,title,jurisdiction,description,now())); return cur.lastrowid
def create_officer(name,badge,role,dept,email):
    with get_conn() as c:
        cur=c.execute("INSERT INTO officers(name,badge_number,role,department,email) VALUES(?,?,?,?,?)",(name,badge,role,dept,email)); return cur.lastrowid
def list_cases():
    with get_conn() as c: return [dict(r) for r in c.execute("SELECT * FROM cases ORDER BY case_id DESC")]
def list_officers():
    with get_conn() as c: return [dict(r) for r in c.execute("SELECT * FROM officers WHERE status='Active' ORDER BY name")]
def list_evidence():
    with get_conn() as c: return [dict(r) for r in c.execute("""SELECT e.evidence_id,e.case_id,c.case_number,e.evidence_type,e.description,e.original_hash,e.status,e.created_at,e.current_custodian_id,o.name AS current_custodian,e.filename FROM evidence e JOIN cases c ON c.case_id=e.case_id LEFT JOIN officers o ON o.officer_id=e.current_custodian_id ORDER BY e.evidence_id DESC""")]
def _event_hash(data): return hashlib.sha256(json.dumps(data,sort_keys=True,default=str).encode()).hexdigest()
def _append_custody(c, values):
    previous=c.execute("SELECT event_hash FROM custody_events WHERE evidence_id=? ORDER BY event_id DESC LIMIT 1",(values[0],)).fetchone()
    prev_hash=previous[0] if previous else "0"*64
    # Canonical event hash includes all persisted event fields and the previous event hash.
    data={"evidence_id":values[0],"from_officer_id":values[1],"to_officer_id":values[2],"event_type":values[3],"event_time":values[4],"location":values[5],"purpose":values[6],"previous_hash":prev_hash}
    digest=_event_hash(data)
    cur=c.execute("INSERT INTO custody_events(evidence_id,from_officer_id,to_officer_id,event_type,event_time,location,purpose,event_hash,blockchain_status,digital_signature) VALUES(?,?,?,?,?,?,?,?,?,?)",(*values,digest,"PENDING","LOCAL-SIMULATION"))
    c.execute("INSERT INTO blockchain_anchors(record_type,record_id,record_hash,transaction_id,anchored_at,status) VALUES('custody_event',?,?,?,?, 'PENDING')",(str(cur.lastrowid),digest,uuid.uuid4().hex,values[4]))
    return cur.lastrowid,digest
def acquire_evidence(case_id,officer_id,etype,description,source,purpose,filename,payload):
    digest=sha256_bytes(payload)  # first hash at acquisition, before user access
    ref=encrypt_file(payload,filename)
    with get_conn() as c:
        cur=c.execute("INSERT INTO evidence(case_id,evidence_type,description,source,original_hash,encrypted_object_ref,created_at,current_custodian_id,filename) VALUES(?,?,?,?,?,?,?,?,?)",(case_id,etype,description,source,digest,ref,now(),officer_id,filename))
        eid=cur.lastrowid; timestamp=now()
        event={"evidence_id":eid,"from":None,"to":officer_id,"event_type":"Seizure","event_time":timestamp,"location":source,"purpose":purpose,"evidence_hash":digest}
        eh=_event_hash(event)
        _append_custody(c,(eid,None,officer_id,"Seizure",timestamp,source,purpose))
        c.execute("INSERT INTO access_logs(evidence_id,officer_id,access_type,access_time,device_id,result,reason) VALUES(?,?,?,?,?,?,?)",(eid,officer_id,"acquire",timestamp,"local-demo","Success",purpose))
        return {"evidence_id":eid,"hash":digest}
def _transfer_evidence(eid,target,location,purpose):
    with get_conn() as c:
        c.execute("BEGIN IMMEDIATE")
        e=c.execute("SELECT * FROM evidence WHERE evidence_id=?",(eid,)).fetchone()
        if not e: raise ValueError("Evidence not found")
        previous=e["current_custodian_id"]
        if previous==target: raise ValueError("The selected officer is already the current custodian.")
        timestamp=now()
        event_id,eh=_append_custody(c,(eid,previous,target,"Transfer",timestamp,location,purpose))
        c.execute("UPDATE evidence SET current_custodian_id=?,status='Transferred' WHERE evidence_id=?",(target,eid))
        c.execute("INSERT INTO access_logs(evidence_id,officer_id,access_type,access_time,device_id,result,reason) VALUES(?,?,?,?,?,?,?)",(eid,previous,"transfer",timestamp,"local-demo","Success",purpose))
        name=c.execute("SELECT name FROM officers WHERE officer_id=?",(target,)).fetchone()["name"]
        c.execute("UPDATE blockchain_anchors SET status='ANCHORED' WHERE record_type='custody_event' AND record_id=?",(str(event_id),))
        c.execute("UPDATE custody_events SET blockchain_status='ANCHORED' WHERE event_id=?",(event_id,))
        c.execute("INSERT INTO transaction_log(operation,outcome,details,recorded_at) VALUES('custody_transfer','SUCCESS',?,?)",(f'evidence={eid}; event={event_id}',timestamp))
        return {"event_id":event_id,"event_hash":eh,"custodian":name}

def transfer_evidence(eid,target,location,purpose):
    try:
        return _transfer_evidence(eid,target,location,purpose)
    except Exception as exc:
        with get_conn() as c:
            c.execute("INSERT INTO transaction_log(operation,outcome,details,recorded_at) VALUES('custody_transfer','FAILURE',?,?)",(f'evidence={eid}; {type(exc).__name__}: {exc}',now()))
        raise
def log_access(eid,oid,kind,result,reason):
    with get_conn() as c: c.execute("INSERT INTO access_logs(evidence_id,officer_id,access_type,access_time,device_id,result,reason) VALUES(?,?,?,?,?,?,?)",(eid,oid,kind,now(),"local-demo",result,reason))
def custody_history(eid):
    """Return the chain-of-custody events for one evidence item."""
    with get_conn() as c:
        rows = c.execute(
            """
            SELECT
                ce.event_id,
                ce.event_type,
                ce.event_time,
                fo.name AS from_officer,
                dest.name AS to_officer,
                ce.location,
                ce.purpose,
                ce.event_hash,
                ce.blockchain_status
            FROM custody_events AS ce
            LEFT JOIN officers AS fo
                ON fo.officer_id = ce.from_officer_id
            LEFT JOIN officers AS dest
                ON dest.officer_id = ce.to_officer_id
            WHERE ce.evidence_id = ?
            ORDER BY ce.event_id
            """,
            (eid,)
        )
        return [dict(row) for row in rows]
def verify_evidence(eid,oid):
    with get_conn() as c:
        e=c.execute("SELECT * FROM evidence WHERE evidence_id=?",(eid,)).fetchone()
        if not e: raise ValueError("Evidence not found")
        try:
            data=decrypt_file(e["encrypted_object_ref"])
            current=sha256_bytes(data)
        except Exception: current=None
        valid=current is not None and current==e["original_hash"]
        c.execute("INSERT INTO access_logs(evidence_id,officer_id,access_type,access_time,device_id,result,reason) VALUES(?,?,?,?,?,?,?)",(eid,oid,"verify",now(),"local-demo","Success" if valid else "Failed","Integrity verification"))
        anchor=c.execute("SELECT * FROM blockchain_anchors WHERE record_type='evidence' AND record_id=? ORDER BY anchor_id DESC LIMIT 1",(str(eid),)).fetchone()
        return {"valid":valid,"original_hash":e["original_hash"],"current_hash":current,"anchor":dict(anchor) if anchor else None}
def create_submission(eid,court,oid,result):
    with get_conn() as c:
        cur=c.execute("INSERT INTO court_submissions(evidence_id,court_name,submitted_by,submission_time,verification_result) VALUES(?,?,?,?,?)",(eid,court,oid,now(),result)); return cur.lastrowid
def dashboard_stats():
    with get_conn() as c:
        return {"Cases":c.execute("SELECT count(*) FROM cases").fetchone()[0],"Officers":c.execute("SELECT count(*) FROM officers").fetchone()[0],"Evidence items":c.execute("SELECT count(*) FROM evidence").fetchone()[0],"Custody events":c.execute("SELECT count(*) FROM custody_events").fetchone()[0]}

def verify_custody_chain(eid):
    with get_conn() as c:
        rows=c.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY event_id",(eid,)).fetchall()
    prev="0"*64; issues=[]
    for r in rows:
        data={"evidence_id":r["evidence_id"],"from_officer_id":r["from_officer_id"],"to_officer_id":r["to_officer_id"],"event_type":r["event_type"],"event_time":r["event_time"],"location":r["location"],"purpose":r["purpose"],"previous_hash":prev}
        expected=_event_hash(data)
        if expected != r["event_hash"]: issues.append(r["event_id"])
        prev=r["event_hash"]
    return {"valid":not issues and bool(rows),"event_count":len(rows),"invalid_event_ids":issues}

def create_backup():
    dest=BACKUP_DIR; dest.mkdir(parents=True,exist_ok=True)
    target=dest/f"eviledger-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.db"
    with get_conn() as source, closing(sqlite3.connect(target)) as out: source.backup(out)
    with closing(sqlite3.connect(target)) as check:
        result=check.execute("PRAGMA integrity_check").fetchone()[0]
        fk=check.execute("PRAGMA foreign_key_check").fetchall()
    with get_conn() as c:
        c.execute("INSERT INTO backup_history(path,created_at,integrity_result) VALUES(?,?,?)",(str(target),now(),result if not fk else "FOREIGN KEY ERRORS"))
    if result!="ok" or fk: target.unlink(missing_ok=True); raise RuntimeError("Backup validation failed")
    return str(target)

def list_backups():
    with get_conn() as c: return [dict(r) for r in c.execute("SELECT * FROM backup_history ORDER BY backup_id DESC")]

def reconcile_pending_anchors():
    """Retry the local ledger write for pending records whose source still exists."""
    resolved=0
    with get_conn() as c:
        pending=c.execute("SELECT * FROM blockchain_anchors WHERE status='PENDING'").fetchall()
        for anchor in pending:
            if anchor["record_type"]=="evidence":
                row=c.execute("SELECT original_hash FROM evidence WHERE evidence_id=?",(anchor["record_id"],)).fetchone()
                valid=row and row[0]==anchor["record_hash"]
            elif anchor["record_type"]=="custody_event":
                row=c.execute("SELECT event_hash FROM custody_events WHERE event_id=?",(anchor["record_id"],)).fetchone()
                valid=row and row[0]==anchor["record_hash"]
            else: valid=False
            if valid:
                c.execute("UPDATE blockchain_anchors SET status='ANCHORED' WHERE anchor_id=?",(anchor["anchor_id"],))
                if anchor["record_type"]=="custody_event":
                    c.execute("UPDATE custody_events SET blockchain_status='ANCHORED' WHERE event_id=?",(anchor["record_id"],))
                resolved+=1
    return resolved

def restore_backup(path):
    src=Path(path).resolve()
    if not src.is_file(): raise ValueError("Backup file does not exist")
    with closing(sqlite3.connect(src)) as c:
        if c.execute("PRAGMA integrity_check").fetchone()[0]!="ok": raise ValueError("Backup integrity check failed")
        if c.execute("PRAGMA foreign_key_check").fetchall(): raise ValueError("Backup has broken relationships")
    create_backup()
    with closing(sqlite3.connect(src)) as source, get_conn() as dest: source.backup(dest)

def dbms_overview():
    with get_conn() as c:
        tables=[r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        stats=dashboard_stats()
        stats["Total tables"]=len(tables)
        stats["Total custody events"]=stats.pop("Custody events")
        return stats,tables

def query_plan():
    with get_conn() as c:
        return [dict(r) for r in c.execute("EXPLAIN QUERY PLAN SELECT * FROM evidence WHERE case_id=? AND original_hash=?",(1,"sample"))]

def analytics():
    with get_conn() as c:
        return {"Evidence by type":[dict(r) for r in c.execute("SELECT evidence_type,COUNT(*) AS total FROM evidence GROUP BY evidence_type ORDER BY total DESC")],"Evidence by case":[dict(r) for r in c.execute("SELECT c.case_number,COUNT(e.evidence_id) AS total FROM cases c LEFT JOIN evidence e USING(case_id) GROUP BY c.case_id HAVING COUNT(e.evidence_id)>=0 ORDER BY total DESC")],"Officer activity":[dict(r) for r in c.execute("SELECT * FROM officer_activity_view ORDER BY access_count DESC")],"Custody statistics":[dict(r) for r in c.execute("SELECT event_type,COUNT(*) AS total FROM custody_events GROUP BY event_type ORDER BY total DESC")],"Court submissions":[dict(r) for r in c.execute("SELECT court_name,COUNT(*) AS total FROM court_submissions GROUP BY court_name ORDER BY total DESC")]}

def authenticate(badge,password):
    import hmac
    with get_conn() as c:
        row=c.execute("SELECT o.officer_id,o.name,o.role,a.password_hash FROM officers o JOIN officer_auth a USING(officer_id) WHERE badge_number=? AND status='Active'",(badge,)).fetchone()
    if not row: return None
    salt,digest=row["password_hash"].split("$",1)
    candidate=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),310000).hex()
    return dict(row) if hmac.compare_digest(candidate,digest) else None

def set_password(officer_id,password):
    if len(password)<12: raise ValueError("Password must be at least 12 characters")
    salt=uuid.uuid4().hex; digest=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),310000).hex()
    with get_conn() as c: c.execute("INSERT INTO officer_auth VALUES(?,?,?) ON CONFLICT(officer_id) DO UPDATE SET password_hash=excluded.password_hash,created_at=excluded.created_at",(officer_id,salt+"$"+digest,now()))

def has_permission(role,code):
    with get_conn() as c: return c.execute("SELECT 1 FROM role_permissions rp JOIN roles r USING(role_id) JOIN permissions p USING(permission_id) WHERE r.name=? AND p.code=?",(role,code)).fetchone() is not None

def seed_demo_data():
    """Add a compact, clearly synthetic India-focused dataset to a new demo database."""
    marker = "DEMO-IND-2026-001"
    with get_conn() as c:
        if c.execute("SELECT 1 FROM cases WHERE case_number=?", (marker,)).fetchone():
            return []
        if c.execute("SELECT count(*) FROM cases").fetchone()[0] or c.execute("SELECT count(*) FROM officers").fetchone()[0]:
            return []

    cases = [
        (marker, "Cybercrime", "UPI impersonation and payment diversion", "Bengaluru City Cyber Crime Police Station", "Synthetic training scenario involving a simulated UPI payment trail. No real people or transactions."),
        ("DEMO-IND-2026-002", "Fraud", "Simulated invoice and vendor portal investigation", "Mumbai Cyber Police, Maharashtra", "Synthetic business email compromise scenario; all names, identifiers, and records are fictional."),
        ("DEMO-IND-2026-003", "Theft", "Transit hub CCTV evidence review", "Delhi Police, New Delhi District", "Synthetic CCTV preservation exercise based at a fictional transit location."),
    ]
    case_ids = [create_case(*row) for row in cases]
    officers = [
        ("Ananya Rao", "KA-DEMO-1042", "Investigating Officer", "Karnataka State Police · Bengaluru City", "ananya.rao@example.invalid"),
        ("Rohan Mehta", "MH-DEMO-2081", "Forensic Analyst", "Maharashtra Police · Mumbai Cyber Unit", "rohan.mehta@example.invalid"),
        ("Ishita Sharma", "DL-DEMO-3117", "Seizing Officer", "Delhi Police · New Delhi District", "ishita.sharma@example.invalid"),
        ("Kabir Nair", "KA-DEMO-1190", "Storage Custodian", "Karnataka State Police · Digital Evidence Store", "kabir.nair@example.invalid"),
    ]
    officer_ids = [create_officer(*row) for row in officers]
    samples = [
        (case_ids[0], officer_ids[0], "Call-detail record", "Synthetic UPI transaction timeline and call-detail extract", "Bengaluru, Karnataka · simulated device K-01", b"EviLedger synthetic training data\nUPI reference: DEMO-UPI-7F31\nNo real account or transaction data.\n"),
        (case_ids[1], officer_ids[1], "Email / chat log", "Synthetic vendor email headers and message export", "Mumbai, Maharashtra · simulated workstation M-04", b"EviLedger synthetic training data\nMessage-ID: demo-mh-2026-0042@example.invalid\nFictional message only.\n"),
        (case_ids[2], officer_ids[2], "CCTV recording", "Synthetic transit-hub CCTV clip manifest", "New Delhi · fictional transit hub camera D-12", b"EviLedger synthetic training data\nCamera: DEMO-DL-12\nClip manifest only; no real footage.\n"),
    ]
    evidence_ids = []
    for idx, (case_id, officer_id, etype, desc, source, payload) in enumerate(samples):
        result = acquire_evidence(case_id, officer_id, etype, desc, source, "Synthetic data for product demonstration", f"synthetic_india_demo_{idx + 1}.txt", payload)
        evidence_ids.append(result["evidence_id"])
        with get_conn() as c:
            c.execute("UPDATE evidence SET status='Under Review' WHERE evidence_id=?", (result["evidence_id"],))
    transfer_evidence(evidence_ids[0], officer_ids[3], "Bengaluru Digital Evidence Store", "Controlled transfer for synthetic demonstration")
    return evidence_ids

if __name__ == "__main__":
    import getpass, sys
    init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        name = input("Administrator name: ").strip()
        badge = input("Unique badge number: ").strip()
        password = getpass.getpass("Password (12+ characters): ")
        with get_conn() as conn:
            existing = conn.execute("SELECT officer_id FROM officers WHERE badge_number=?", (badge,)).fetchone()
            officer_id = existing[0] if existing else create_officer(name, badge, "Administrator", "System Administration", None)
        set_password(officer_id, password)
        print("Administrator account created. Sign in with the badge number and password.")
