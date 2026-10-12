"""Pictures and videos: thumbnails (upright, bounded, decompression bombs refused), camera metadata through ExifTool, when a
picture was taken (its offset, its GPS time, the computer's zone), GPS, video details and keyframes (ffmpeg), and OCR of
pictures and scanned PDFs (tesseract)."""
import io
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

from app.forensic import media as md
from app.forensic.modules import PROFILES, REGISTRY, plan
from app.forensic.modules.base import run_tool
from app.forensic.textextract import method_for

T = lambda *a: datetime(*a, tzinfo=timezone.utc)


def _jpeg(path, size=(640, 480), orientation=1, **ifd):
    img = Image.new('RGB', size, (40, 90, 160))
    ImageDraw.Draw(img).rectangle((0, 0, size[0] // 4, size[1] // 4), fill=(255, 0, 0))  # a red corner, to see the turn
    exif = Image.Exif()
    exif[0x010F], exif[0x0110], exif[0x0112] = 'Google', 'Pixel 8', orientation
    e = exif.get_ifd(0x8769)
    for k, v in ifd.items():
        e[{'original': 0x9003, 'offset': 0x9011}[k]] = v
    img.save(path, 'JPEG', exif=exif)
    return path


def test_thumbnail_is_upright_bounded_and_keeps_the_original_size(tmp_path):
    info = md.thumbnail(_jpeg(tmp_path / 'a.jpg', orientation=6), tmp_path / 't.jpg')
    assert info == {'width': 640, 'height': 480, 'format': 'JPEG'}
    with Image.open(tmp_path / 't.jpg') as t:
        assert t.format == 'JPEG' and t.size == (240, 320)  # turned a quarter (orientation 6), long side 320
        assert t.getpixel((t.width - 5, 5))[0] > 200          # the red corner is now at the top right
    Image.new('RGBA', (50, 30), (0, 255, 0, 128)).save(tmp_path / 'small.png')
    assert md.thumbnail(tmp_path / 'small.png', tmp_path / 's.jpg')['format'] == 'PNG'
    with Image.open(tmp_path / 's.jpg') as t:
        assert t.size == (50, 30) and t.mode == 'RGB'  # never enlarged


def test_bombs_and_non_pictures_are_refused(tmp_path):
    Image.new('L', (9000, 9000)).save(tmp_path / 'bomb.png')  # 81 million pixels, a few kilobytes on disk
    assert (tmp_path / 'bomb.png').stat().st_size < 200_000
    with pytest.raises(ValueError):
        md.thumbnail(tmp_path / 'bomb.png', tmp_path / 'b.jpg')
    assert not (tmp_path / 'b.jpg').exists()
    (tmp_path / 'x.jpg').write_bytes(b'not a picture at all')
    with pytest.raises(ValueError):
        md.thumbnail(tmp_path / 'x.jpg', tmp_path / 'x-t.jpg')


def test_when_a_picture_was_taken():
    assert md.exif_time('2026:09:01 10:10:32') == (datetime(2026, 9, 1, 10, 10, 32), None)
    assert md.exif_time('0000:00:00 00:00:00') == (None, None) and md.exif_time('yesterday') == (None, None)
    assert md.exif_time('2026:09:01 10:10:32.25+02:00') == (datetime(2026, 9, 1, 10, 10, 32, 250000), '+02:00')
    t = md.taken_time({'DateTimeOriginal': '2026:09:01 10:10:32', 'OffsetTimeOriginal': '-04:00'}, 'Asia/Kolkata')
    assert t['taken'] == T(2026, 9, 1, 14, 10, 32) and t['taken_basis'] == 'offset -04:00 in the picture'
    t = md.taken_time({'DateTimeOriginal': '2026:09:01 10:10:32', 'GPSDateTime': '2026:09:01 14:10:30Z'}, None)
    assert t['taken'] == T(2026, 9, 1, 14, 10, 32) and t['taken_basis'] == 'GPS time in the picture'
    summer = md.taken_time({'DateTimeOriginal': '2026:08:30 18:15:00'}, 'America/New_York')
    winter = md.taken_time({'DateTimeOriginal': '2026:01:15 18:15:00'}, 'America/New_York')
    assert summer['taken'] == T(2026, 8, 30, 22, 15) and winter['taken'] == T(2026, 1, 15, 23, 15)  # EDT, then EST
    assert summer['taken_basis'] == "computer's time zone (America/New_York)" and summer['taken_local'] == '2026-08-30 18:15:00'
    none = md.taken_time({'CreateDate': '2026:08:30 18:15:00'}, None)
    assert none['taken'] == T(2026, 8, 30, 18, 15) and none['taken_basis'] == 'no time zone: shown as recorded'
    assert md.taken_time({}, 'UTC') == {}


def test_locations_and_cameras():
    assert md.gps_of({'GPSLatitude': 42.3601, 'GPSLongitude': -71.0589, 'GPSAltitude': 12.54}) == {'lat': 42.3601, 'lon': -71.0589, 'alt': 12.5}
    assert md.gps_of({'GPSCoordinates': '-33.8568 151.2153 4'}) == {'lat': -33.8568, 'lon': 151.2153, 'alt': 4.0}
    assert md.gps_of({'GPSLatitude': 0, 'GPSLongitude': 0}) is None  # a camera without a fix writes zeros
    assert md.gps_of({'GPSLatitude': 95, 'GPSLongitude': 10}) is None and md.gps_of({}) is None
    assert md.iso6709('+42.3601-071.0589+012.500/') == {'lat': 42.3601, 'lon': -71.0589, 'alt': 12.5}
    assert md.iso6709('+48.8584+002.2945/') == {'lat': 48.8584, 'lon': 2.2945, 'alt': None} and md.iso6709('nowhere') is None
    assert md.metadata({'Make': 'Canon', 'Model': 'Canon EOS 80D'})['camera'] == 'Canon EOS 80D'
    assert md.metadata({'Make': 'Google', 'Model': 'Pixel 8'})['camera'] == 'Google Pixel 8'
    assert md.metadata({'FileType': 'PNG'}) == {'exif': {'FileType': 'PNG'}, 'camera': None}


def test_exiftool_batch_reads_camera_time_and_gps(tmp_path):
    a = _jpeg(tmp_path / 'one photo.jpg', original='2026:09:01 10:10:32', offset='-04:00')
    img = Image.open(a)
    exif = img.getexif()
    gps = exif.get_ifd(0x8825)
    gps.update({1: 'S', 2: (33.0, 51.0, 24.48), 3: 'E', 4: (151.0, 12.0, 55.08)})
    img.save(tmp_path / 'gps.jpg', exif=exif)
    rows = md.exif_batch([a, tmp_path / 'gps.jpg', tmp_path / 'missing.jpg'], run_tool, tmp_path / 'w')
    one = rows[str(a)]
    assert (one['Make'], one['Model'], one['DateTimeOriginal'], one['OffsetTimeOriginal']) == ('Google', 'Pixel 8', '2026:09:01 10:10:32', '-04:00')
    g = md.gps_of(rows[str(tmp_path / 'gps.jpg')])
    assert g['lat'] == pytest.approx(-33.8568, abs=1e-4) and g['lon'] == pytest.approx(151.2153, abs=1e-4)
    assert str(tmp_path / 'missing.jpg') not in rows and md.exif_batch([], run_tool, tmp_path) == {}


def _video(path, scenes):
    srcs = {'testsrc': 'testsrc=size=160x120:rate=10:duration=1', 'bars': 'smptebars=size=160x120:rate=10:duration=1',
            'red': 'color=c=red:size=160x120:rate=10:duration=1', 'blue': 'color=c=blue:size=160x120:rate=10:duration=3'}
    args = ['ffmpeg', '-v', 'error', '-y']
    for s in scenes:
        args += ['-f', 'lavfi', '-i', srcs[s]]
    args += ['-filter_complex', ''.join(f'[{i}:v]' for i in range(len(scenes))) + f'concat=n={len(scenes)}:v=1:a=0[v]', '-map', '[v]',
             '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-metadata', 'creation_time=2026-09-01T14:18:00Z',
             '-metadata', 'location=+42.3601-071.0589/', str(path)]
    subprocess.run(args, check=True)
    return path


def test_video_details_and_scene_keyframes(tmp_path):
    v = md.probe(_video(tmp_path / 'clip.mp4', ['testsrc', 'bars', 'red']), run_tool)
    assert (v['duration'], v['width'], v['height'], v['video_codec'], v['frame_rate']) == (3.0, 160, 120, 'h264', 10.0)
    assert v['recorded'] == T(2026, 9, 1, 14, 18) and md.iso6709(v['location'])['lat'] == 42.3601 and v['audio_codec'] is None
    frames = md.keyframes(tmp_path / 'clip.mp4', tmp_path / 'f', 'abc', v['duration'], run_tool)
    assert [f['method'] for f in frames] == ['scene change'] * 3 and [round(f['time']) for f in frames] == [0, 1, 2]
    with Image.open(tmp_path / 'f' / frames[2]['file']) as last:
        r, g, b = last.convert('RGB').resize((1, 1)).getpixel((0, 0))
        assert r > 200 and g < 60 and b < 60  # the third scene is red
    one = md.probe(_video(tmp_path / 'still.mp4', ['blue']), run_tool)
    frames = md.keyframes(tmp_path / 'still.mp4', tmp_path / 'g', 'def', one['duration'], run_tool)
    assert [f['method'] for f in frames] == ['even interval'] * 3 and [f['time'] for f in frames] == [0.5, 1.5, 2.5]
    (tmp_path / 'broken.mp4').write_bytes(b'\x00' * 2000)
    with pytest.raises(ValueError):
        md.probe(tmp_path / 'broken.mp4', run_tool)


def _text_image(lines, size=(1000, 300)):
    img = Image.new('L', size, 250)
    d = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        d.text((40, 40 + i * 90), line, fill=10, font=ImageFont.load_default(size=56))
    return img


def test_ocr_of_a_picture_and_of_a_scanned_pdf(tmp_path):
    _text_image(['INVOICE 4471', 'PAID IN FULL']).save(tmp_path / 'note.png')
    text = md.ocr_image(tmp_path / 'note.png', tmp_path / 'w', run_tool)
    assert 'INVOICE' in text and '4471' in text and 'PAID' in text
    _text_image(['TRANSFER ORDER', 'ACCOUNT 12345678'], (1240, 600)).save(tmp_path / 'scan.pdf', 'PDF', resolution=150)
    assert md.pdf_needs_ocr(tmp_path / 'scan.pdf', run_tool)
    text, pages = md.ocr_pdf(tmp_path / 'scan.pdf', tmp_path / 'p', run_tool)
    assert pages == 1 and 'TRANSFER ORDER' in text and '12345678' in text
    assert not list((tmp_path / 'p').glob('page-*.png'))  # rendered pages are removed
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(tmp_path / 'typed.pdf'))
    c.drawString(72, 720, 'This page has real text in it, so it needs no OCR at all.')
    c.save()
    assert not md.pdf_needs_ocr(tmp_path / 'typed.pdf', run_tool)
    assert md.clean_text('a  b\r\n\n\n\nc') == 'a b\n\nc'
    assert method_for({'size': 10, 'mime': 'image/png', 'file_category': 'image', 'ocr': {'text': 'x'}}) == 'ocr'
    assert method_for({'size': 10, 'mime': 'image/png', 'file_category': 'image'}) is None


def test_modules():
    assert 'media' in PROFILES['standard'] and 'ocr' not in PROFILES['standard'] and {'media', 'ocr'} <= set(PROFILES['full'])
    assert REGISTRY['media'].requires == ('fileproc',) and 'ocr' in REGISTRY['content'].follows
    done = {m: {'status': 'COMPLETED', 'version': REGISTRY[m].version} for m in PROFILES['full']}
    assert plan(['media'], done) == ['media', 'ocr', 'content', 'found_data']
    assert plan(['ocr'], {}) == ['tz_probe', 'fs_index', 'fileproc', 'ocr']
