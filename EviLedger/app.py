from datetime import datetime, timezone
from pathlib import Path
from html import escape
import streamlit as st
from database import init_db, seed_demo_data, get_conn, create_case, create_officer, list_cases, list_officers, acquire_evidence, transfer_evidence, log_access, list_evidence, custody_history, verify_evidence, create_submission, dashboard_stats, verify_custody_chain, dbms_overview, analytics, query_plan, create_backup, list_backups, restore_backup, authenticate, has_permission, reconcile_pending_anchors
from security import encrypt_file
from ledger import anchor_record, verify_anchor
from reports import build_certificate

st.set_page_config(page_title="EviLedger", page_icon="🔐", layout="wide")
init_db()
seed_demo_data()
with get_conn() as startup_conn:
    evidence_to_anchor=[dict(row) for row in startup_conn.execute("SELECT e.evidence_id,e.original_hash FROM evidence e WHERE NOT EXISTS (SELECT 1 FROM blockchain_anchors a WHERE a.record_type='evidence' AND a.record_id=CAST(e.evidence_id AS TEXT))")]
for row in evidence_to_anchor:
    anchor_record("evidence",str(row["evidence_id"]),row["original_hash"])
st.markdown("""
<style>
.block-container {padding:1.2rem 2.35rem 3.25rem;max-width:1560px}
.hero {display:flex;align-items:center;justify-content:space-between;padding:1rem 1.4rem;border-radius:13px;background:var(--secondary-background-color);color:var(--text-color);margin-bottom:1.65rem;border:1px solid var(--border-color)}
.brand {display:flex;align-items:center;gap:.75rem}.brand-mark {height:39px;width:39px;border-radius:11px;background:var(--background-color);color:var(--primary-color);display:grid;place-items:center;font-size:1.25rem;font-weight:800}
.brand-name {font-size:1.08rem;font-weight:750;letter-spacing:-.02em;color:var(--text-color)}.brand-sub {font-size:.76rem;color:var(--text-color);opacity:.7;margin-top:.12rem}
.header-status {color:var(--text-color);opacity:.75;font-size:.78rem;font-weight:650;letter-spacing:.04em}.header-dot {display:inline-block;background:#2b9b78;height:8px;width:8px;border-radius:50%;margin-right:.45rem}
.page-kicker,.dashboard-subtitle,.kpi-label,.kpi-note,.section-heading,.panel-title,.activity-row,.activity-time {color:var(--text-color);opacity:.78}
.page-kicker {font-size:.72rem;font-weight:750;letter-spacing:.12em;text-transform:uppercase;margin:0 0 .45rem}
.dashboard-title {font-size:2rem;font-weight:760;letter-spacing:-.045em;color:var(--text-color);margin:0}.dashboard-subtitle {margin:.35rem 0 1.35rem;font-size:.97rem}
.kpi,.panel,div[data-testid="stMetric"],div[data-testid="stForm"] {background:var(--secondary-background-color);border:1px solid var(--border-color);border-radius:12px}
.kpi {padding:1.05rem 1.12rem;min-height:112px}.kpi-label {font-size:.79rem;font-weight:600}.kpi-value {font-size:1.85rem;line-height:1.15;color:var(--text-color);font-weight:760;letter-spacing:-.04em;margin:.42rem 0 .2rem}.kpi-note {font-size:.75rem}
.section-heading {font-size:1.03rem;font-weight:720;margin:.1rem 0 .85rem;letter-spacing:-.015em}
.panel {padding:1.1rem 1.15rem;min-height:178px}
.panel-title {font-weight:720;font-size:.9rem;margin-bottom:.9rem}.activity-row {padding:.62rem 0;border-top:1px solid var(--border-color);font-size:.8rem}.activity-time {font-size:.72rem;margin-top:.18rem}
.status-pill {display:inline-block;padding:.2rem .55rem;background:var(--secondary-background-color);color:var(--text-color);border:1px solid var(--border-color);border-radius:99px;font-size:.7rem;font-weight:700}
div[data-testid="stMetric"] {padding:1rem 1.15rem} div[data-testid="stMetricLabel"],div[data-testid="stMetricValue"] {color:var(--text-color)}
div[data-testid="stForm"] {padding:1.2rem}
.stButton>button,.stFormSubmitButton>button {border-radius:8px;font-weight:650;min-height:2.55rem}
[data-testid="stDataFrame"] {border:1px solid var(--border-color);border-radius:10px;overflow:hidden}
h2,h3 {letter-spacing:-.025em;color:var(--text-color)}
@media(max-width:800px){.block-container{padding:.9rem}.hero{padding:.8rem}.dashboard-title{font-size:1.65rem}.header-status{display:none}}
</style>
""", unsafe_allow_html=True)
st.markdown('<div class="hero"><div class="brand"><div class="brand-mark">E</div><div><div class="brand-name">EviLedger</div><div class="brand-sub">Evidence integrity platform</div></div></div><div class="header-status"><span class="header-dot"></span>LOCAL SYSTEM ACTIVE</div></div>', unsafe_allow_html=True)

with st.sidebar:
    st.title("EviLedger")
    if "user" not in st.session_state:
        st.subheader("Sign in")
        with st.form("login"):
            badge=st.text_input("Badge number")
            password=st.text_input("Password",type="password")
            login=st.form_submit_button("Sign in")
        if login:
            user=authenticate(badge.strip(),password)
            if user: st.session_state["user"]=user; st.rerun()
            st.error("Invalid badge number or password.")
        st.caption("First run: create the initial administrator from Terminal with `python database.py create-admin`.")
        st.stop()
    current=st.session_state["user"]
    st.caption(f"Signed in: {current['name']} · {current['role']}")
    if st.button("Sign out"): del st.session_state["user"]; st.rerun()
    pages=["Dashboard","Cases","Officers","Acquire Evidence","Evidence Vault","Custody Transfer","Integrity Verification","Court Reports","Audit Ledger","DBMS CONTROL CENTER"]
    permission_for={"Dashboard":"case.view","Cases":"case.view","Officers":"users.manage","Acquire Evidence":"evidence.acquire","Evidence Vault":"evidence.view","Custody Transfer":"evidence.transfer","Integrity Verification":"evidence.verify","Court Reports":"court.manage","Audit Ledger":"audit.view","DBMS CONTROL CENTER":"audit.view"}
    pages=[name for name in pages if has_permission(current["role"],permission_for[name])]
    page=st.radio("Navigation",pages)
    st.caption("LOCAL DEMO ENVIRONMENT · LOCAL STORAGE")
    st.info("All preloaded case records are synthetic and intended for demonstration only.")

if page=="Dashboard":
    stats=dashboard_stats()
    rows=list_evidence()
    cases=list_cases()
    with get_conn() as conn:
        anchor_count=conn.execute("SELECT count(*) FROM blockchain_anchors WHERE status='ANCHORED'").fetchone()[0]
        activity=[dict(r) for r in conn.execute("""SELECT ce.event_type,ce.event_time,ce.location,e.evidence_id,e.description,o.name AS officer
            FROM custody_events ce JOIN evidence e ON e.evidence_id=ce.evidence_id
            JOIN officers o ON o.officer_id=ce.to_officer_id ORDER BY ce.event_id DESC LIMIT 4""")]
    st.markdown('<div class="page-kicker">Operations overview</div><div class="dashboard-title">Evidence operations</div><div class="dashboard-subtitle">A clear view of case activity, registered evidence, and chain-of-custody events.</div>', unsafe_allow_html=True)
    metrics=[("Cases managed",stats["Cases"],"Across all investigations"),("Evidence items",stats["Evidence items"],"Registered and protected"),("Custody events",stats["Custody events"],"Recorded handoffs and intake"),("Ledger anchors",anchor_count,"Integrity records anchored")]
    metric_cols=st.columns(4)
    for col,(label,value,note) in zip(metric_cols,metrics):
        col.markdown(f'<div class="kpi"><div class="kpi-label">{label}</div><div class="kpi-value">{value}</div><div class="kpi-note">{note}</div></div>',unsafe_allow_html=True)
    st.write("")
    left,right=st.columns([1.55,1],gap="large")
    with left:
        st.markdown('<div class="section-heading">Recent evidence</div>',unsafe_allow_html=True)
        if rows:
            recent=[{"Evidence":"E-"+str(r["evidence_id"]),"Case reference":r["case_number"],"Type":r["evidence_type"],"Description":r["description"],"Custodian":r["current_custodian"] or "Unassigned","Status":r["status"]} for r in rows[:6]]
            st.dataframe(recent,hide_index=True,height=278,column_config={"Evidence":st.column_config.TextColumn(width="small"),"Case reference":st.column_config.TextColumn(width="medium"),"Description":st.column_config.TextColumn(width="large"),"Status":st.column_config.TextColumn(width="small")})
        else:
            st.info("No evidence is registered yet. Add a case and officer, then acquire evidence.")
    with right:
        st.markdown('<div class="section-heading">Recent custody activity</div>',unsafe_allow_html=True)
        if activity:
            events_html="".join(f'<div class="activity-row"><b>{escape(str(r["event_type"]))}</b> · E-{r["evidence_id"]} — {escape(str(r["officer"]))}<div class="activity-time">{escape(str(r["location"] or "Location not recorded"))}</div></div>' for r in activity)
            st.markdown(f'<div class="panel"><div class="panel-title">Latest recorded events <span class="status-pill">UP TO DATE</span></div>{events_html}</div>',unsafe_allow_html=True)
        else:
            st.markdown('<div class="panel"><div class="panel-title">Latest recorded events</div><div class="activity-row">Custody events will appear here after evidence is acquired or transferred.</div></div>',unsafe_allow_html=True)
    st.write("")
    bottom_left,bottom_right=st.columns([1.55,1],gap="large")
    with bottom_left:
        st.markdown('<div class="section-heading">Case portfolio</div>',unsafe_allow_html=True)
        if cases:
            case_rows=[{"Case reference":c["case_number"],"Investigation":c["title"] or c["case_type"],"Jurisdiction":c["jurisdiction"] or "—","Status":c["status"]} for c in cases[:5]]
            st.dataframe(case_rows,hide_index=True,height=220)
        else: st.info("No cases have been created.")
    with bottom_right:
        st.markdown('<div class="section-heading">Evidence lifecycle</div><div class="panel"><div class="panel-title">A traceable path from intake to reporting</div><div class="activity-row">01 &nbsp; Acquire and fingerprint</div><div class="activity-row">02 &nbsp; Encrypt and register</div><div class="activity-row">03 &nbsp; Record custody transfers</div><div class="activity-row">04 &nbsp; Verify integrity and report</div></div>',unsafe_allow_html=True)
    st.caption("Local demonstration environment · The audit ledger is simulated · Preloaded records are synthetic.")

elif page=="Cases":
    st.subheader("Investigation cases")
    with st.form("case_form"):
        a,b=st.columns(2)
        number=a.text_input("Official case number *")
        typ=b.selectbox("Case type",["Cybercrime","Theft","Fraud","Murder","Missing person","Other"])
        title=a.text_input("Case title")
        jurisdiction=b.text_input("Jurisdiction / police station")
        description=st.text_area("Description")
        submitted=st.form_submit_button("Create case")
    if submitted:
        if not number.strip(): st.error("Case number is required.")
        else:
            try: st.success(f"Created case #{create_case(number,typ,title,jurisdiction,description)}")
            except Exception as e: st.error(str(e))
    st.dataframe(list_cases(),hide_index=True)

elif page=="Officers":
    st.subheader("Authorized personnel")
    with st.form("officer_form"):
        a,b=st.columns(2)
        name=a.text_input("Full name *"); badge=b.text_input("Badge / staff ID *")
        role=a.selectbox("Role",["Seizing Officer","Investigating Officer","Forensic Analyst","Storage Custodian","Court Officer","Auditor","Administrator"])
        dept=b.text_input("Department / organization")
        email=a.text_input("Email (optional)")
        ok=st.form_submit_button("Add officer")
    if ok:
        if not name.strip() or not badge.strip(): st.error("Name and badge are required.")
        else:
            try: st.success(f"Officer added (ID {create_officer(name,badge,role,dept,email)}).")
            except Exception as e: st.error(str(e))
    st.dataframe(list_officers(),hide_index=True)

elif page=="Acquire Evidence":
    st.subheader("Acquire and register evidence")
    cases=list_cases(); officers=list_officers()
    if not cases or not officers:
        st.warning("Create at least one case and one officer first.")
    else:
        with st.form("evidence_form"):
            case_options={f'{x["case_number"]} — {x["title"] or x["case_type"]} (ID {x["case_id"]})':x["case_id"] for x in cases}
            officer_options={f'{x["name"]} — {x["role"]} (ID {x["officer_id"]})':x["officer_id"] for x in officers}
            case_label=st.selectbox("Related case",list(case_options))
            officer_label=st.selectbox("Acquiring officer",list(officer_options))
            etype=st.selectbox("Evidence type",["Mobile phone image","CCTV recording","Computer / disk image","Call-detail record","Email / chat log","GPS / transport log","Forensic report","Other"])
            desc=st.text_area("Evidence description *")
            source=st.text_input("Source device / collection location")
            purpose=st.text_input("Acquisition purpose",value="Initial seizure and preservation")
            uploaded=st.file_uploader("Select evidence file *")
            go=st.form_submit_button("Hash, encrypt and register")
        if go:
            if not uploaded or not desc.strip(): st.error("A file and description are required.")
            else:
                try:
                    payload=uploaded.getvalue()
                    result=acquire_evidence(case_options[case_label],officer_options[officer_label],etype,desc,source,purpose,uploaded.name,payload)
                    anchor=anchor_record("evidence",str(result["evidence_id"]),result["hash"])
                    st.success(f"Evidence E-{result['evidence_id']} acquired. SHA-256 generated before storage; encrypted file saved.")
                    st.code(result["hash"])
                    st.caption(f"Audit anchor: {anchor['transaction_id']} · {anchor['status']}")
                except Exception as e: st.error(str(e))

elif page=="Evidence Vault":
    st.subheader("Evidence register")
    rows=list_evidence()
    if rows: st.dataframe(rows,hide_index=True)
    else: st.info("No evidence records available.")
    st.caption("Evidence binaries are encrypted at rest. This academic prototype keeps files in the local storage folder.")

elif page=="Custody Transfer":
    st.subheader("Controlled custody transfer")
    evid=list_evidence(); officers=list_officers()
    if not evid or not officers: st.warning("Register evidence and officers first.")
    else:
        with st.form("transfer_form"):
            eopts={f'E-{e["evidence_id"]} · {e["description"][:55]}':e["evidence_id"] for e in evid}
            ekey=st.selectbox("Evidence",list(eopts))
            oopts={f'{o["name"]} — {o["role"]} (ID {o["officer_id"]})':o["officer_id"] for o in officers}
            target=st.selectbox("New custodian",list(oopts))
            location=st.text_input("Transfer location")
            reason=st.text_area("Purpose / reason")
            ok=st.form_submit_button("Commit transfer")
        if ok:
            try:
                result=transfer_evidence(eopts[ekey],oopts[target],location,reason)
                anch=anchor_record("custody_event",str(result["event_id"]),result["event_hash"])
                st.success(f"Transfer committed atomically. New custodian: {result['custodian']}.")
                st.caption(f"Ledger: {anch['transaction_id']}")
            except Exception as ex: st.error(str(ex))
    if evid:
        selected=st.selectbox("View custody history for evidence ID", [e["evidence_id"] for e in evid])
        st.dataframe(custody_history(selected),hide_index=True)

elif page=="Integrity Verification":
    st.subheader("Verify evidence integrity")
    evid=list_evidence()
    if not evid: st.info("No evidence to verify.")
    else:
        options={f'E-{e["evidence_id"]} · {e["description"][:60]}':e["evidence_id"] for e in evid}
        selected=st.selectbox("Evidence item",list(options))
        officer=st.selectbox("Auditing officer",list_officers(),format_func=lambda x:f'{x["name"]} ({x["role"]})')
        if st.button("Recalculate SHA-256 and verify"):
            result=verify_evidence(options[selected],officer["officer_id"])
            if result["valid"]: st.success("Integrity verified: current file hash matches acquisition hash.")
            else: st.error("Integrity check FAILED. The file may be missing or modified.")
            st.write("Original hash"); st.code(result["original_hash"])
            st.write("Current hash"); st.code(result["current_hash"] or "Unavailable")
            if result.get("anchor"): st.write("Ledger anchor:", "Verified" if verify_anchor(result["anchor"]["record_hash"]) else "Not found / mismatch")

elif page=="Court Reports":
    st.subheader("Court submission and integrity certificate")
    evid=list_evidence(); officers=list_officers()
    if not evid or not officers: st.info("Evidence and officers are required.")
    else:
        eopts={f'E-{e["evidence_id"]} · {e["description"][:55]}':e for e in evid}
        label=st.selectbox("Evidence",list(eopts))
        court=st.text_input("Court / authority name")
        officer=st.selectbox("Submitted by",officers,format_func=lambda x:f'{x["name"]} ({x["role"]})')
        if st.button("Verify and generate certificate"):
            e=eopts[label]; check=verify_evidence(e["evidence_id"],officer["officer_id"])
            if not check["valid"]: st.error("Cannot submit: evidence integrity verification failed.")
            elif not court.strip(): st.error("Enter court name.")
            else:
                sid=create_submission(e["evidence_id"],court,officer["officer_id"],"Verified")
                pdf=build_certificate(e,court,officer,sid,custody_history(e["evidence_id"]),check)
                st.success(f"Submission record #{sid} created.")
                st.download_button("Download evidence integrity certificate (PDF)",pdf,file_name=f"EviLedger_certificate_{e['evidence_id']}.pdf",mime="application/pdf")

elif page=="Audit Ledger":
    st.subheader("Independent audit ledger")
    with get_conn() as conn:
        anchors=[dict(r) for r in conn.execute("SELECT * FROM blockchain_anchors ORDER BY anchor_id DESC")]
    if anchors: st.dataframe(anchors,hide_index=True)
    else: st.info("No anchors yet. Evidence acquisition and custody transfers create anchors.")
    st.caption("Prototype ledger entries contain hashes and identifiers only—not evidence files or confidential evidence contents.")

elif page=="DBMS CONTROL CENTER":
    st.title("DBMS CONTROL CENTER")
    st.caption("SQLite relational controls and a local hash-ledger simulation; this is not a distributed blockchain.")
    stats,tables=dbms_overview()
    cols=st.columns(5)
    for col,label in zip(cols,["Total tables","Cases","Officers","Evidence items","Total custody events"]): col.metric(label,stats.get(label,0),border=True)
    overview,schema,sql,tx,integrity,optimization,backup,security=st.tabs(["Overview","Schema","SQL analytics","Transactions","Integrity","Query plans","Backup & recovery","Permissions"])
    with overview:
        st.write("Normalized reference catalogs support roles, permissions, departments, event types, courts, and evidence types.")
        st.dataframe([{"Table":x} for x in tables],hide_index=True)
    with schema:
        with get_conn() as c:
            details=[]
            for table in tables:
                for col in c.execute(f'PRAGMA table_info("{table}")'):
                    details.append({"Table":table,"Column":col["name"],"Primary key":bool(col["pk"]),"Required":bool(col["notnull"])})
            fks=[]
            for table in tables:
                fks.extend({"Table":table,**dict(x)} for x in c.execute(f'PRAGMA foreign_key_list("{table}")'))
        st.dataframe(details,hide_index=True); st.subheader("Foreign key relationships"); st.dataframe(fks,hide_index=True)
        st.code("erDiagram\n CASES ||--o{ EVIDENCE : contains\n OFFICERS ||--o{ CUSTODY_EVENTS : handles\n EVIDENCE ||--o{ CUSTODY_EVENTS : tracks\n EVIDENCE ||--o{ ACCESS_LOGS : accessed\n OFFICERS ||--o{ OFFICER_AUTH : authenticates\n ROLES ||--o{ ROLE_PERMISSIONS : grants\n PERMISSIONS ||--o{ ROLE_PERMISSIONS : includes")
    with sql:
        for label,rows in analytics().items():
            st.subheader(label); st.dataframe(rows,hide_index=True)
    with tx:
        st.write("A rollback demonstration inserts a temporary synthetic row inside a savepoint, then rolls it back.")
        if st.button("Run safe commit / rollback demonstration"):
            with get_conn() as c:
                c.execute("SAVEPOINT demo_tx")
                c.execute("INSERT INTO transaction_log(operation,outcome,details,recorded_at) VALUES('demo','SUCCESS','temporary row',?)",(datetime.now(timezone.utc).isoformat(),))
                c.execute("ROLLBACK TO demo_tx"); c.execute("RELEASE demo_tx")
                c.execute("INSERT INTO transaction_log(operation,outcome,details,recorded_at) VALUES('demo_rollback','SUCCESS','temporary insert rolled back',?)",(datetime.now(timezone.utc).isoformat(),))
            st.success("Temporary insert rolled back; demonstration result recorded.")
        with get_conn() as c: st.dataframe([dict(r) for r in c.execute("SELECT * FROM transaction_log ORDER BY transaction_id DESC LIMIT 30")],hide_index=True)
    with integrity:
        evid=list_evidence()
        if evid:
            eid=st.selectbox("Evidence for chain verification",[x["evidence_id"] for x in evid])
            result=verify_custody_chain(eid)
            (st.success if result["valid"] else st.error)(f"Chain {'valid' if result['valid'] else 'invalid'} · {result['event_count']} events · invalid IDs: {result['invalid_event_ids']}")
            if st.button("Verify selected evidence file"):
                check=verify_evidence(eid,current["officer_id"]); (st.success if check["valid"] else st.error)("Evidence bytes match original SHA-256." if check["valid"] else "Evidence integrity check failed.")
        if st.button("Reconcile pending local anchors"):
            st.success(f"Reconciled {reconcile_pending_anchors()} pending anchor(s).")
        with get_conn() as c: st.dataframe([dict(r) for r in c.execute("SELECT anchor_id,record_type,record_id,record_hash,status,anchored_at FROM blockchain_anchors ORDER BY anchor_id DESC")],hide_index=True)
    with optimization:
        st.dataframe(query_plan(),hide_index=True); st.caption("The composite case/hash and custody/officer indexes reduce table scans for filtered lookups.")
    with backup:
        if st.button("Create validated database backup"):
            try: st.success(f"Backup created: {create_backup()}")
            except Exception as exc: st.error(str(exc))
        backups=list_backups(); st.dataframe(backups,hide_index=True)
        if backups:
            selected_backup=st.selectbox("Validated backup to restore",[x["path"] for x in backups])
            confirm=st.checkbox("I understand restore replaces current database contents after making a recovery backup")
            if st.button("Restore selected backup",disabled=not confirm):
                try: restore_backup(selected_backup); st.success("Backup restored and validated.")
                except Exception as exc: st.error(str(exc))
        if st.button("Run PRAGMA integrity_check"):
            with get_conn() as c: st.code(str(c.execute("PRAGMA integrity_check").fetchone()[0])); st.write("Foreign key violations:",len(c.execute("PRAGMA foreign_key_check").fetchall()))
    with security:
        with get_conn() as c:
            matrix=[dict(r) for r in c.execute("SELECT r.name AS role,p.code AS permission,p.description FROM role_permissions rp JOIN roles r USING(role_id) JOIN permissions p USING(permission_id) ORDER BY r.name,p.code")]
        st.dataframe(matrix,hide_index=True)
        required="users.manage"
        if has_permission(current["role"],required): st.success(f"Authorized: {current['role']} has {required}.")
        else: st.error(f"Controlled denial: {current['role']} lacks {required}; officer administration is denied.")
