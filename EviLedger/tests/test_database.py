import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database
import security
from reports import build_certificate


class DatabaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        (root / "encrypted").mkdir()
        self.patches = [
            patch.object(database, "DB", root / "test.db"),
            patch.object(database, "BACKUP_DIR", root / "backups"),
            patch.object(database, "STORAGE", root / "encrypted"),
            patch.object(security, "STORAGE", root / "encrypted"),
            patch.object(security, "KEY_PATH", root / "key"),
            patch.dict("os.environ", {"EVILEDGER_FERNET_KEY": ""}),
        ]
        for item in self.patches:
            item.start()
        database.init_db()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def fixture(self):
        case_id = database.create_case("SYN-1", "Training", "Synthetic case", "Lab", "No real records")
        officer_id = database.create_officer("Synthetic Officer", "SYN-1", "Seizing Officer", "Lab", None)
        evidence = database.acquire_evidence(case_id, officer_id, "Text file", "Synthetic bytes", "Lab", "Test", "sample.txt", b"synthetic evidence")
        return case_id, officer_id, evidence

    def test_crud_constraints_rbac_and_acquisition_integrity(self):
        case_id, officer_id, evidence = self.fixture()
        with self.assertRaises(sqlite3.IntegrityError):
            database.create_case("SYN-1", "Training", "Duplicate", "Lab", "")
        with self.assertRaises(sqlite3.IntegrityError):
            database.create_officer("Other", "SYN-1", "Auditor", "Lab", None)
        with self.assertRaises(sqlite3.IntegrityError):
            database.create_officer("Bad role", "SYN-BAD", "Root", "Lab", None)
        with self.assertRaises(sqlite3.IntegrityError):
            with database.get_conn() as conn:
                conn.execute("INSERT INTO evidence(case_id) VALUES(99999)")
        self.assertTrue(database.has_permission("Seizing Officer", "evidence.acquire"))
        self.assertFalse(database.has_permission("Seizing Officer", "users.manage"))
        verified = database.verify_evidence(evidence["evidence_id"], officer_id)
        self.assertTrue(verified["valid"])
        with self.assertRaises(sqlite3.IntegrityError):
            with database.get_conn() as conn:
                conn.execute("UPDATE evidence SET original_hash='tampered' WHERE evidence_id=?", (evidence["evidence_id"],))

    def test_transfer_is_atomic_and_chain_is_linked(self):
        _, officer_id, evidence = self.fixture()
        target = database.create_officer("Synthetic Custodian", "SYN-2", "Storage Custodian", "Lab", None)
        eid = evidence["evidence_id"]
        result = database.transfer_evidence(eid, target, "Lab vault", "Synthetic handoff")
        self.assertEqual(result["custodian"], "Synthetic Custodian")
        self.assertTrue(database.verify_custody_chain(eid)["valid"])
        with database.get_conn() as conn:
            before = conn.execute("SELECT COUNT(*) FROM custody_events WHERE evidence_id=?", (eid,)).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            database.transfer_evidence(eid, 99999, "Nowhere", "Invalid target")
        with database.get_conn() as conn:
            after = conn.execute("SELECT COUNT(*) FROM custody_events WHERE evidence_id=?", (eid,)).fetchone()[0]
            self.assertEqual(conn.execute("SELECT current_custodian_id FROM evidence WHERE evidence_id=?", (eid,)).fetchone()[0], target)
            self.assertEqual(conn.execute("SELECT outcome FROM transaction_log WHERE operation='custody_transfer' ORDER BY transaction_id DESC LIMIT 1").fetchone()[0], "FAILURE")
        self.assertEqual(before, after)

    def test_hash_chain_detects_tampering_and_passwords_are_hashed(self):
        _, officer_id, evidence = self.fixture()
        eid = evidence["evidence_id"]
        self.assertTrue(database.verify_custody_chain(eid)["valid"])
        database.set_password(officer_id, "synthetic-password-12")
        self.assertTrue(database.authenticate("SYN-1", "synthetic-password-12"))
        self.assertIsNone(database.authenticate("SYN-1", "incorrect"))
        with database.get_conn() as conn:
            conn.execute("DROP TRIGGER custody_events_immutable_update")
            conn.execute("UPDATE custody_events SET purpose='tampered' WHERE evidence_id=?", (eid,))
        self.assertFalse(database.verify_custody_chain(eid)["valid"])

    def test_backup_restore_and_pdf_report(self):
        case_id, officer_id, evidence = self.fixture()
        backup = database.create_backup()
        with database.get_conn() as conn:
            conn.execute("UPDATE cases SET title='Changed after backup' WHERE case_id=?", (case_id,))
        database.restore_backup(backup)
        with database.get_conn() as conn:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertFalse(conn.execute("PRAGMA foreign_key_check").fetchall())
            self.assertEqual(conn.execute("SELECT title FROM cases WHERE case_id=?", (case_id,)).fetchone()[0], "Synthetic case")
        pdf = build_certificate({"evidence_id": evidence["evidence_id"], "case_id": case_id, "evidence_type": "Text", "description": "Synthetic", "original_hash": evidence["hash"]}, "Synthetic Court", {"name": "Test Officer"}, 1, [], {"valid": True})
        self.assertTrue(pdf.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
