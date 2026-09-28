from pathlib import Path
import hashlib, mimetypes
from datetime import datetime, timezone
from .tools import parse_mmls, parse_filesystem, filesystem_stats
from .hashing import sha256_file

class ForensicEngine:
    """Orchestrates safe forensic examination; original evidence is never modified."""
    def analyze(self, evidence_path: Path, format_name: str, progress=None):
        if progress: progress(30, 'inventorying-image')
        result={'status':'COMPLETED','format':format_name,'engine':'DFIP Forensic Orchestrator',
                'artifacts':[],'limitations':[]}
        try:
            size=evidence_path.stat().st_size
            result['file_size']=size
            result['mime_type']=mimetypes.guess_type(evidence_path.name)[0] or 'application/octet-stream'
            result['sha256']=sha256_file(evidence_path)
        except Exception as e:
            result['status']='FAILED';result['error']=str(e);return result
        if format_name.upper() in {'E01','EX01','AFF','AFF4','RAW','DD'}:
            result['partitions']=parse_mmls(evidence_path)
            if progress: progress(45, 'parsing-partitions')
            partitions=result['partitions'].get('partitions',[])
            offsets=[p['start'] for p in partitions if not p.get('is_meta') and not p.get('is_unallocated') and 'extended' not in p.get('description','').lower()] or [0]
            seen=set()
            for offset in offsets[:8]:
                if offset in seen: continue
                seen.add(offset)
                result['filesystem_offset_'+str(offset)]=parse_filesystem(evidence_path,format_name,offset)
                if progress: progress(min(85, 50 + len(seen)*10), 'filesystem-examination')
                result['filesystem_stats_'+str(offset)]=filesystem_stats(evidence_path,offset)
        return result

def extract_demo_artifacts(case_id,evidence_id):
    now=datetime.now(timezone.utc)
    return [
      {'case_id':case_id,'evidence_id':evidence_id,'type':'FILE_ACCESS','timestamp':now,'description':'Demo artifact: sensitive document accessed during investigation window.','source':'DEMO_DATA'},
      {'case_id':case_id,'evidence_id':evidence_id,'type':'USB_ACTIVITY','timestamp':now,'description':'Demo artifact: removable media connection observed.','source':'DEMO_DATA'},
      {'case_id':case_id,'evidence_id':evidence_id,'type':'BROWSER_ACTIVITY','timestamp':now,'description':'Demo artifact: browser activity record available for review.','source':'DEMO_DATA'}]
