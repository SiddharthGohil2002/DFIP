"""Pictures and videos: thumbnails, camera metadata (EXIF and others, through ExifTool), video details and keyframes
(ffprobe and ffmpeg), and text read from pictures and scanned PDFs (tesseract).

Untrusted media is decoded under limits: Pillow refuses pictures over MAX_PIXELS (decompression bombs), and the external
tools run through run_tool with a timeout and a memory limit. Thumbnails are JPEGs written under the SHA-256 of the file
they show, never under a name from the evidence.

Times: a picture's DateTimeOriginal is local time without a zone. It becomes UTC through, in order, its own offset
(OffsetTimeOriginal), the GPS time stamp of the same picture, or the computer's time zone; the basis is recorded. Video
creation times (QuickTime/MP4) are UTC by the format.
"""
from __future__ import annotations
import json
import re
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

MAX_PIXELS = 64_000_000
THUMB_SIZE = 320
MAX_FRAMES = 6
EXIF_BATCH = 200
EXIF_TIMEOUT = 300
FFPROBE_TIMEOUT = 60
FFMPEG_TIMEOUT = 180
OCR_TIMEOUT = 120
OCR_MAX_CHARS = 64 * 1024
OCR_MAX_PAGES = 10
OCR_MIN_SIZE = (200, 60)
EXIF_TAGS = ['-Make', '-Model', '-LensModel', '-Software', '-Orientation', '-DateTimeOriginal', '-CreateDate', '-ModifyDate',
             '-OffsetTimeOriginal', '-OffsetTime', '-SubSecTimeOriginal', '-GPSLatitude', '-GPSLongitude', '-GPSAltitude',
             '-GPSDateTime', '-ImageWidth', '-ImageHeight', '-FileType', '-MIMEType', '-Artist', '-Copyright', '-SerialNumber',
             '-ImageUniqueID', '-ImageDescription', '-UserComment', '-XPComment', '-Duration', '-GPSCoordinates', '-HostComputer']


def _limits():
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS  # over twice this, Pillow refuses to open; over it, the checks below refuse
    return Image


def thumbnail(src: Path, dest: Path) -> dict:
    """A JPEG thumbnail (at most THUMB_SIZE pixels on its long side, turned upright by its EXIF orientation) of a picture.
    Returns the picture's own width, height and format; raises ValueError for what can't or mustn't be decoded."""
    Image = _limits()
    from PIL import ImageOps
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', Image.DecompressionBombWarning)  # refused just below, by size
            img = Image.open(src)
        with img:
            width, height, fmt = img.width, img.height, img.format
            if width * height > MAX_PIXELS:
                raise ValueError(f'{width} x {height} pixels is over the {MAX_PIXELS:,}-pixel limit')
            img.draft('RGB', (THUMB_SIZE * 2, THUMB_SIZE * 2))  # JPEG: decode at a reduced scale
            img = ImageOps.exif_transpose(img)
            if img.mode not in ('RGB', 'L'):
                img = img.convert('RGB')
            img.thumbnail((THUMB_SIZE, THUMB_SIZE))
            dest.parent.mkdir(parents=True, exist_ok=True)
            img.save(dest, 'JPEG', quality=80)
    except Image.DecompressionBombError as exc:
        raise ValueError(f'refused as a decompression bomb: {exc}') from exc
    except (OSError, SyntaxError, ValueError, Image.UnidentifiedImageError) as exc:
        raise ValueError(str(exc)[:200]) from exc
    return {'width': width, 'height': height, 'format': fmt}


def exif_batch(paths: list[Path], run_tool, work: Path) -> dict[str, dict]:
    """Metadata of many files from one ExifTool run: {path: {tag: value}} (numbers as numbers, GPS as signed decimals)."""
    if not paths:
        return {}
    work.mkdir(parents=True, exist_ok=True)
    args = work / 'exiftool-args.txt'
    args.write_text('\n'.join(str(p) for p in paths) + '\n', encoding='utf-8')
    r = run_tool(['exiftool', '-j', '-n', '-q', '-q', '-charset', 'filename=utf8', '-api', 'LargeFileSupport=1', *EXIF_TAGS, '-@', str(args)],
                 timeout=EXIF_TIMEOUT)
    try:
        rows = json.loads(r.get('stdout') or '[]')
    except ValueError:
        return {}
    return {row.get('SourceFile'): row for row in rows if isinstance(row, dict)}


_EXIF_TIME = re.compile(r'^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([+-]\d{2}):?(\d{2})|Z)?$')
_OFFSET = re.compile(r'^([+-])(\d{2}):?(\d{2})$')


def exif_time(value) -> tuple[datetime | None, str | None]:
    """(naive local time, offset string) of an EXIF date like '2026:09:01 10:10:32', or (None, None)."""
    m = _EXIF_TIME.match(str(value or '').strip())
    if not m or m.group(1) == '0000':
        return None, None
    try:
        t = datetime(*(int(m.group(i)) for i in range(1, 7)), int((m.group(7) or '0')[:6].ljust(6, '0')))
    except ValueError:
        return None, None
    off = f'{m.group(8)}:{m.group(9)}' if m.group(8) else ('+00:00' if str(value).endswith('Z') else None)
    return t, off


def taken_time(meta: dict, zone: str | None) -> dict:
    """When the picture was taken, in UTC, with the basis: its own offset, the GPS time, the computer's zone, or none."""
    local, inline = exif_time(meta.get('DateTimeOriginal') or meta.get('CreateDate'))
    if local is None:
        return {}
    out = {'taken_local': local.strftime('%Y-%m-%d %H:%M:%S')}
    off = inline or (str(meta.get('OffsetTimeOriginal') or meta.get('OffsetTime') or '').strip() or None)
    m = _OFFSET.match(off or '')
    if m:
        sign = 1 if m.group(1) == '+' else -1
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3))) * sign
        out.update(taken=(local - delta).replace(tzinfo=timezone.utc), taken_basis=f'offset {off} in the picture')
        return out
    gps, _ = exif_time(meta.get('GPSDateTime'))
    if gps is not None and abs((gps - local).total_seconds()) < 15 * 3600:
        # The GPS stamp is UTC: the whole-quarter-hour difference to the local time is the camera's offset.
        diff = round((local - gps).total_seconds() / 900) * 900
        out.update(taken=(local - timedelta(seconds=diff)).replace(tzinfo=timezone.utc), taken_basis='GPS time in the picture')
        return out
    if zone:
        try:
            out.update(taken=local.replace(tzinfo=ZoneInfo(zone)).astimezone(timezone.utc), taken_basis=f"computer's time zone ({zone})")
            return out
        except (KeyError, ValueError):
            pass
    out.update(taken=local.replace(tzinfo=timezone.utc), taken_basis='no time zone: shown as recorded')
    return out


def gps_of(meta: dict) -> dict | None:
    lat, lon = meta.get('GPSLatitude'), meta.get('GPSLongitude')
    if (lat is None or lon is None) and meta.get('GPSCoordinates'):
        parts = str(meta['GPSCoordinates']).split()
        if len(parts) >= 2:
            lat, lon = parts[0], parts[1]
            meta.setdefault('GPSAltitude', parts[2] if len(parts) > 2 else None)
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    alt = meta.get('GPSAltitude')
    try:
        alt = round(float(alt), 1) if alt is not None else None
    except (TypeError, ValueError):
        alt = None
    return {'lat': round(lat, 6), 'lon': round(lon, 6), 'alt': alt}


def metadata(meta: dict) -> dict:
    """The camera and description fields worth showing, from an ExifTool row."""
    keep = ('Make', 'Model', 'LensModel', 'Software', 'Orientation', 'DateTimeOriginal', 'CreateDate', 'ModifyDate', 'OffsetTimeOriginal',
            'GPSDateTime', 'Artist', 'Copyright', 'SerialNumber', 'ImageUniqueID', 'ImageDescription', 'UserComment', 'XPComment',
            'HostComputer', 'FileType', 'MIMEType')
    out = {k: (str(meta[k])[:500] if isinstance(meta[k], str) else meta[k]) for k in keep if meta.get(k) not in (None, '')}
    make, model = (meta.get('Make') or '').strip(), (meta.get('Model') or '').strip()
    camera = model if make and model.lower().startswith(make.lower()) else ' '.join(x for x in (make, model) if x)
    return {'exif': out, 'camera': camera or None}


# -- video ----------------------------------------------------------------------------------------------------------
def probe(src: Path, run_tool) -> dict:
    r = run_tool(['ffprobe', '-v', 'error', '-print_format', 'json', '-show_format', '-show_streams', str(src)], timeout=FFPROBE_TIMEOUT)
    try:
        data = json.loads(r.get('stdout') or '{}')
    except ValueError:
        data = {}
    if not data.get('streams'):
        raise ValueError((r.get('stderr') or 'ffprobe found no streams').strip()[:200])
    fmt = data.get('format') or {}
    video = next((s for s in data['streams'] if s.get('codec_type') == 'video' and not (s.get('disposition') or {}).get('attached_pic')), None)
    audio = next((s for s in data['streams'] if s.get('codec_type') == 'audio'), None)
    tags = {k.lower(): v for k, v in (fmt.get('tags') or {}).items()}
    out = {'duration': round(float(fmt['duration']), 3) if fmt.get('duration') not in (None, 'N/A') else None,
           'container': fmt.get('format_name'), 'bit_rate': int(fmt['bit_rate']) if str(fmt.get('bit_rate', '')).isdigit() else None,
           'video_codec': video.get('codec_name') if video else None, 'audio_codec': audio.get('codec_name') if audio else None,
           'width': video.get('width') if video else None, 'height': video.get('height') if video else None,
           'frame_rate': _rate(video.get('avg_frame_rate')) if video else None,
           'encoder': tags.get('encoder'), 'title': tags.get('title'), 'location': tags.get('location') or tags.get('com.apple.quicktime.location.iso6709')}
    ct = tags.get('creation_time') or tags.get('com.apple.quicktime.creationdate')
    if ct:
        try:
            out['recorded'] = datetime.fromisoformat(ct.replace('Z', '+00:00')).astimezone(timezone.utc)
        except ValueError:
            pass
    return out


def _rate(v):
    try:
        a, b = str(v).split('/')
        return round(int(a) / int(b), 3) if int(b) else None
    except ValueError:
        return None


ISO6709 = re.compile(r'^([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)?/?$')


def iso6709(value: str | None) -> dict | None:
    """A QuickTime location ('+42.3601-071.0589+012.500/') as {lat, lon, alt}."""
    m = ISO6709.match((value or '').strip())
    if not m:
        return None
    return gps_of({'GPSLatitude': m.group(1), 'GPSLongitude': m.group(2), 'GPSAltitude': m.group(3)})


def keyframes(src: Path, dest_dir: Path, stem: str, duration: float | None, run_tool) -> list[dict]:
    """Up to MAX_FRAMES frames: the first and every scene change (ffmpeg's scene score over 0.3); when that finds fewer than
    three, frames at even intervals instead. Returns [{time, file}] with the JPEG names in dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    pattern = dest_dir / f'{stem}-scene-%02d.jpg'
    r = run_tool(['ffmpeg', '-hide_banner', '-nostdin', '-v', 'info', '-i', str(src), '-vf',
                  f"select='eq(n,0)+gt(scene,0.3)',showinfo,scale={THUMB_SIZE}:-2", '-vsync', 'vfr', '-frames:v', str(MAX_FRAMES),
                  '-q:v', '5', str(pattern)], timeout=FFMPEG_TIMEOUT)
    times = [float(t) for t in re.findall(r'pts_time:([0-9.]+)', r.get('stderr') or '')]
    files = sorted(dest_dir.glob(f'{stem}-scene-*.jpg'))
    frames = [{'time': round(times[i], 3) if i < len(times) else None, 'file': f.name, 'method': 'scene change'} for i, f in enumerate(files)]
    if len(frames) >= 3 or not duration:
        return frames
    for f in files:
        f.unlink(missing_ok=True)
    frames = []
    n = min(MAX_FRAMES, 3 if duration < 10 else MAX_FRAMES)
    for i in range(n):
        t = round(duration * (i + 0.5) / n, 3)
        out = dest_dir / f'{stem}-at-{i + 1:02d}.jpg'
        run_tool(['ffmpeg', '-hide_banner', '-nostdin', '-v', 'error', '-ss', str(t), '-i', str(src), '-frames:v', '1',
                  '-vf', f'scale={THUMB_SIZE}:-2', '-q:v', '5', '-y', str(out)], timeout=FFMPEG_TIMEOUT)
        if out.is_file() and out.stat().st_size:
            frames.append({'time': t, 'file': out.name, 'method': 'even interval'})
    return frames


# -- text in pictures (OCR) -----------------------------------------------------------------------------------------
def ocr_image(src: Path, work: Path, run_tool) -> str:
    """The text tesseract reads in a picture (converted to an upright greyscale PNG first, at most 4,000 pixels across)."""
    Image = _limits()
    from PIL import ImageOps
    work.mkdir(parents=True, exist_ok=True)
    png = work / 'ocr-input.png'
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', Image.DecompressionBombWarning)  # refused just below, by size
            img = Image.open(src)
        with img:
            if img.width * img.height > MAX_PIXELS:
                raise ValueError('over the pixel limit')
            img = ImageOps.exif_transpose(img).convert('L')
            if max(img.size) > 4000:
                img.thumbnail((4000, 4000))
            img.save(png)
    except (Image.DecompressionBombError, OSError, SyntaxError, Image.UnidentifiedImageError) as exc:
        raise ValueError(str(exc)[:200]) from exc
    try:
        return _tesseract(png, run_tool)
    finally:
        png.unlink(missing_ok=True)


def _tesseract(png: Path, run_tool) -> str:
    r = run_tool(['tesseract', str(png), 'stdout', '-l', 'eng', '--psm', '3'], timeout=OCR_TIMEOUT)
    if r.get('status') != 'COMPLETED':
        raise ValueError((r.get('stderr') or r.get('status') or 'tesseract failed').strip()[:200])
    return clean_text(r.get('stdout') or '')


def clean_text(text: str) -> str:
    text = re.sub(r'[ \t\f\v]+', ' ', text.replace('\r', ''))
    return re.sub(r'\n\s*\n+', '\n\n', text).strip()[:OCR_MAX_CHARS]


def pdf_needs_ocr(src: Path, run_tool) -> bool:
    """A PDF whose pages carry (almost) no text: a scan."""
    r = run_tool(['pdftotext', '-l', str(OCR_MAX_PAGES), '-q', str(src), '-'], timeout=OCR_TIMEOUT)
    return r.get('status') == 'COMPLETED' and len(re.sub(r'\s', '', r.get('stdout') or '')) < 20


def ocr_pdf(src: Path, work: Path, run_tool) -> tuple[str, int]:
    """The text tesseract reads on the first OCR_MAX_PAGES pages of a scanned PDF (rendered at 200 dpi by pdftoppm)."""
    work.mkdir(parents=True, exist_ok=True)
    prefix = work / 'page'
    run_tool(['pdftoppm', '-r', '200', '-gray', '-png', '-l', str(OCR_MAX_PAGES), str(src), str(prefix)], timeout=OCR_TIMEOUT)
    pages = sorted(work.glob('page-*.png'))
    texts = []
    try:
        for p in pages:
            texts.append(_tesseract(p, run_tool))
    finally:
        for p in pages:
            p.unlink(missing_ok=True)
    return clean_text('\n\n'.join(t for t in texts if t)), len(pages)
