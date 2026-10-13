"""The custody form of a physical evidence item (PDF): what the item is, its seals, photos, every custody action
recorded in DFIP, and blank rows for the signatures of whoever hands the item over and receives it from now on."""
from __future__ import annotations
import io
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .report_pdf import BODY, CELL, H1, H2, NOTE, PAGE_WIDTH, _fmt, _table

ACTIONS = {'RECEIVED': 'Received into storage', 'CHECK_OUT': 'Checked out', 'CHECK_IN': 'Checked in', 'TRANSFER': 'Moved',
           'RELEASE': 'Released', 'DESTROY': 'Destroyed'}
BLANK_ROWS = 6


def _detail(e: dict) -> str:
    parts = []
    if e.get('person'):
        parts.append(f'to {e["person"]}' if e['action'] in ('CHECK_OUT', 'RELEASE') else e['person'])
    if e.get('location'):
        parts.append(f'kept at {e["location"]}')
    if e.get('purpose'):
        parts.append(f'for {e["purpose"]}')
    if e.get('seal_intact') is not None:
        parts.append('seal intact' if e['seal_intact'] else 'SEAL BROKEN')
    if e.get('seal_number'):
        parts.append(f'seal {e["seal_number"]}')
    if e.get('notes'):
        parts.append(e['notes'])
    return '; '.join(parts)


def build(item: dict, case: dict, user: dict, folder: Path) -> bytes:
    buf = io.BytesIO()
    now = datetime.now(timezone.utc)
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
                            title=f'Custody form {item["item_id"]}', author='DFIP')
    story = [Paragraph('Physical evidence custody form', H1),
             Paragraph(escape(f'{item["item_id"]} · case {case["case_id"]} ({case.get("name")})'), BODY), Spacer(1, 6)]
    rows = [('Description', item.get('description')), ('Kind', item.get('kind')),
            ('Make and model', ' '.join(x for x in (item.get('make'), item.get('model')) if x) or None),
            ('Serial number', item.get('serial_number')), ('Bag number', item.get('bag_number')), ('Seal number (current)', item.get('seal_number')),
            ('Seized', ' · '.join(x for x in (_fmt(item.get('seized_at')) if item.get('seized_at') else None, item.get('seized_from'),
                                              f'by {item["seized_by"]}' if item.get('seized_by') else None) if x) or None),
            ('Status', (item.get('status') or '').replace('_', ' ').lower()), ('Kept at', item.get('location')),
            ('Held by', (item.get('holder') or {}).get('person')), ('Disk images made from it', item.get('evidence_ids') or None),
            ('Notes', item.get('notes'))]
    t = Table([[Paragraph(f'<b>{escape(k)}</b>', CELL), Paragraph(escape(_fmt(v)), CELL)] for k, v in rows],
              colWidths=[PAGE_WIDTH * .28, PAGE_WIDTH * .72])
    t.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), .3, colors.HexColor('#b0b8c0')), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                           ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e7eef5'))]))
    story += [t, Spacer(1, 8)]
    photos = [p for p in item.get('photos') or [] if (folder / p['file']).is_file()][:4]
    if photos:
        story.append(Paragraph('Photos', H2))
        cells = []
        for p in photos:
            img = Image(str(folder / p['file']))
            scale = min(40 * mm / img.imageWidth, 40 * mm / img.imageHeight)
            img.drawWidth, img.drawHeight = img.imageWidth * scale, img.imageHeight * scale
            cells.append([img, Paragraph(escape(f'{p.get("caption") or p.get("name")} · SHA-256 {p["sha256"][:16]}…'), CELL)])
        pt = Table([[c[0] for c in cells], [c[1] for c in cells]], colWidths=[PAGE_WIDTH / 4] * len(cells))
        pt.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP')]))
        story += [pt, Spacer(1, 8)]
    story.append(Paragraph('Custody recorded in DFIP', H2))
    story.append(_table(['Time (UTC)', 'Action', 'Recorded by', 'Details'],
                        [[e.get('at'), ACTIONS.get(e.get('action'), e.get('action')), e.get('by_name'), _detail(e)] for e in item.get('custody') or []],
                        [1.4, 1.1, 1.2, 3.3]))
    story += [Spacer(1, 8), Paragraph('Further transfers (to be signed)', H2),
              Paragraph('Each person handing the item over and each person receiving it signs, with the date and time and the seal number '
                        'and whether the seal was intact.', NOTE), Spacer(1, 4)]
    blank = [[Paragraph(f'<b>{h}</b>', CELL) for h in ('Date and time', 'Released by (name, signature)', 'Received by (name, signature)',
                                                         'Purpose', 'Seal number / intact?')]]
    blank += [[''] * 5 for _ in range(BLANK_ROWS)]
    bt = Table(blank, colWidths=[PAGE_WIDTH * w for w in (.16, .25, .25, .18, .16)], rowHeights=[None] + [11 * mm] * BLANK_ROWS)
    bt.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), .3, colors.HexColor('#b0b8c0')), ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e7eef5'))]))
    story += [bt, Spacer(1, 10),
              Paragraph(escape(f'Printed by {user.get("name")} on {now:%Y-%m-%d %H:%M} UTC from DFIP. The custody recorded above is kept in DFIP '
                               f'with every change in its audit trail.'), NOTE)]
    doc.build(story)
    return buf.getvalue()
