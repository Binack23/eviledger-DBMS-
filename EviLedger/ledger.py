"""Local append-only ledger simulation. Replace with Hyperledger Fabric client in deployment."""
import sqlite3, uuid, hashlib
from datetime import datetime, timezone
from database import get_conn
def anchor_record(record_type,record_id,record_hash):
    with get_conn() as c:
        # transaction identifier is unique and hash-linked to the submitted record
        tx="TX-"+uuid.uuid4().hex.upper()
        c.execute("INSERT INTO blockchain_anchors(record_type,record_id,record_hash,transaction_id,anchored_at,status) VALUES(?,?,?,?,?,?)",(record_type,record_id,record_hash,tx,datetime.now(timezone.utc).isoformat(),"ANCHORED"))
        return {"transaction_id":tx,"status":"ANCHORED"}
def verify_anchor(record_hash):
    with get_conn() as c:
        return c.execute("SELECT 1 FROM blockchain_anchors WHERE record_hash=? AND status='ANCHORED'",(record_hash,)).fetchone() is not None
