from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
from datetime import datetime, timezone
import hashlib
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from ..security import current_user, require_desktop_workstation, require_permission
from ..database import get_db
from ..core.config import settings
from ..repositories.cases import get_case
from ..services.audit import log
from ..websocket.manager import manager

r = APIRouter(prefix='/reports', tags=['reports'])

def serial(x):
    d = dict(x)
    d['_id'] = str(d['_id'])
    for k, v in list(d.items()):
        if hasattr(v, 'isoformat'):
            d[k] = v.isoformat()
    return d

@r.get('')
def reports(u=Depends(current_user)):
    docs = []
    for x in get_db()['reports'].find().sort('created_at', -1).limit(100):
        if get_case(x['case_id'], u):
            docs.append(serial(x))
    return {'data': docs}

@r.post('')
def create_report(case_id: str, u=Depends(require_desktop_workstation)):
    case = get_case(case_id, u)
    if not case:
        raise HTTPException(404, 'Case not found or access denied')
    db = get_db()
    rid = f"RPT-{db['reports'].count_documents({}) + 1:03d}"
    root = Path(settings.storage_path) / 'reports'
    root.mkdir(parents=True, exist_ok=True)
    path = root / f'{rid}.pdf'
    styles = getSampleStyleSheet()
    now = datetime.now(timezone.utc)
    
    evid = list(db['evidence'].find({'case_id': case_id}))
    findings = list(db['findings'].find({'case_id': case_id}))
    events = list(db['timeline_events'].find({'case_id': case_id}).sort('timestamp', 1).limit(1000))
    
    story = [
        Paragraph('DFIP — Digital Forensics Investigation Report', styles['Title']),
        Spacer(1, 12),
        Paragraph(f'Report ID: {rid}', styles['BodyText']),
        Paragraph(f"Case: {case_id} — {case['name']}", styles['BodyText']),
        Paragraph(f'Generated: {now.isoformat()}', styles['BodyText']),
        Spacer(1, 18),
        Paragraph('Evidence Register', styles['Heading2'])
    ]
    data = [['Evidence', 'Format', 'SHA-256', 'Status']] + [
        [e['evidence_id'], e['format'], e['sha256'][:32] + '…', e.get('verification_status', 'NOT_VERIFIED')]
        for e in evid
    ]
    if len(data) == 1:
        data.append(['—', '—', '—', 'No evidence'])
    t = Table(data, colWidths=[75, 55, 250, 90])
    t.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), .4, colors.grey),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e7eef5')),
        ('FONTSIZE', (0, 0), (-1, -1), 8)
    ]))
    story += [t, Spacer(1, 16), Paragraph('Findings', styles['Heading2'])]
    for f in findings:
        story.append(Paragraph(f"<b>{f['title']}</b> [{f['severity']}] — {f['description']}", styles['BodyText']))
    story += [Spacer(1, 12), Paragraph('Timeline', styles['Heading2'])]
    for e in events:
        story.append(Paragraph(f"{e['timestamp'].isoformat()} — {e.get('type', 'EVENT')} — {e.get('description', '')}", styles['BodyText']))
    story += [
        Spacer(1, 16),
        Paragraph('Evidence integrity is represented by recorded cryptographic hashes and audit history. Investigators should preserve source media and follow applicable legal procedures.', styles['BodyText'])
    ]
    SimpleDocTemplate(str(path), pagesize=A4).build(story)
    pdf_bytes = path.read_bytes()
    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    
    doc = {
        'report_id': rid,
        'case_id': case_id,
        'path': str(path.resolve()),
        'created_at': now,
        'created_by': str(u['_id']),
        'version': 1,
        'sha256': pdf_sha256
    }
    db['reports'].insert_one(doc)
    log(u, 'REPORT_GENERATED', 'report', rid, {'case_id': case_id, 'sha256': pdf_sha256})
    
    manager.emit_sync('REPORT_GENERATED', {
        'report_id': rid,
        'case_id': case_id,
        'sha256': pdf_sha256,
        'created_at': now.isoformat()
    })
    return serial(doc)

@r.get('/{rid}/download')
def download_report(rid, u=Depends(current_user)):
    x = get_db()['reports'].find_one({'report_id': rid})
    if not x or not get_case(x['case_id'], u):
        raise HTTPException(404, 'Report not found')
    p = Path(x['path'])
    if not p.exists():
        raise HTTPException(410, 'Report file unavailable')
    return FileResponse(
        str(p),
        media_type='application/pdf',
        filename=f'{rid}.pdf',
        headers={'X-DFIP-Report-SHA256': x.get('sha256', '')}
    )
