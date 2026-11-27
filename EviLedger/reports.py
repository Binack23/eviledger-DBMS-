from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
def build_certificate(evidence,court,officer,submission_id,history,check):
    buf=BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=42,leftMargin=42,topMargin=42,bottomMargin=42)
    styles=getSampleStyleSheet(); story=[]
    story += [Paragraph("EviLedger — Evidence Integrity Certificate",styles["Title"]),Paragraph("Academic prototype report • Not a statutory legal certificate",styles["Italic"]),Spacer(1,16)]
    data=[["Submission ID",str(submission_id)],["Court / authority",court],["Evidence ID",f"E-{evidence['evidence_id']}"],["Case ID",str(evidence["case_id"])],["Evidence type",evidence["evidence_type"]],["Description",evidence["description"]],["Original SHA-256",evidence["original_hash"]],["Verification result","VERIFIED" if check["valid"] else "FAILED"],["Submitted by",officer["name"]],["Generated (UTC)",__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()]]
    t=Table(data,colWidths=[125,360]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#eaf0f7")),("GRID",(0,0),(-1,-1),.5,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),8),("WORDWRAP",(1,0),(1,-1),True)])); story += [t,Spacer(1,18),Paragraph("Chain-of-custody history",styles["Heading2"])]
    rows=[["Event","Time (UTC)","From","To","Location","Purpose"]]
    for x in history: rows.append([x["event_type"],x["event_time"],x["from_officer"] or "—",x["to_officer"],x["location"] or "—",x["purpose"] or "—"])
    ht=Table(rows,repeatRows=1,colWidths=[48,95,65,65,85,100]); ht.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dce8f4")),("GRID",(0,0),(-1,-1),.4,colors.grey),("FONTSIZE",(0,0),(-1,-1),6),("VALIGN",(0,0),(-1,-1),"TOP")]))
    story += [ht,Spacer(1,16),Paragraph("This report summarizes the prototype's recorded metadata and hash verification. It does not independently establish legal admissibility. A competent authority must determine compliance with applicable law, including the Bharatiya Sakshya Adhiniyam, 2023.",styles["BodyText"])]
    doc.build(story); return buf.getvalue()
