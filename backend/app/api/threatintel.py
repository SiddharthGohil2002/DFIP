from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timezone
from ..security import current_user, require_permission
from ..database import get_db
from ..repositories.cases import get_case
from ..repositories.evidence import get_evidence
from ..services.audit import log
from ..threatintel import client as ti

r = APIRouter(prefix='/threat-intel', tags=['threat-intel'])


def serial(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: serial(x) for k, x in v.items()}
    if isinstance(v, list):
        return [serial(x) for x in v]
    return v


@r.get('/providers')
def providers(u=Depends(current_user)):
    """Reports which providers are actually configured with API keys, so the
    frontend can show real availability instead of implying every integration
    is live."""
    from ..core.config import settings
    return {
        'virustotal': bool(settings.virustotal_api_key),
        'abuseipdb': bool(settings.abuseipdb_api_key),
        'otx': bool(settings.otx_api_key),
        'urlhaus': bool(settings.urlhaus_api_key),
    }


@r.post('/hash/{file_hash}')
def lookup_hash(file_hash: str, case_id: str, u=Depends(require_permission('ANALYSIS_RUN'))):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    vt = ti.lookup_virustotal_hash(file_hash)
    otx = ti.lookup_otx(file_hash, indicator_type='file')
    result = {'indicator': file_hash, 'case_id': case_id, 'virustotal': serial(vt), 'otx': serial(otx)}
    get_db()['forensic_artifacts'].insert_one({
        'case_id': case_id, 'type': 'THREAT_INTEL_HASH', 'timestamp': datetime.now(timezone.utc),
        'data': result, 'source': 'THREAT_INTEL',
    })
    log(u, 'THREAT_INTEL_HASH_LOOKUP', 'case', case_id, {'indicator': file_hash})
    return result


@r.post('/ip/{ip_address}')
def lookup_ip(ip_address: str, case_id: str, u=Depends(require_permission('ANALYSIS_RUN'))):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    abuse = ti.lookup_abuseipdb(ip_address)
    otx = ti.lookup_otx(ip_address, indicator_type='IPv4')
    result = {'indicator': ip_address, 'case_id': case_id, 'abuseipdb': serial(abuse), 'otx': serial(otx)}
    get_db()['forensic_artifacts'].insert_one({
        'case_id': case_id, 'type': 'THREAT_INTEL_IP', 'timestamp': datetime.now(timezone.utc),
        'data': result, 'source': 'THREAT_INTEL',
    })
    log(u, 'THREAT_INTEL_IP_LOOKUP', 'case', case_id, {'indicator': ip_address})
    return result


@r.post('/domain/{domain}')
def lookup_domain(domain: str, case_id: str, u=Depends(require_permission('ANALYSIS_RUN'))):
    if not get_case(case_id, u):
        raise HTTPException(404, 'Case not found or access denied')
    urlhaus = ti.lookup_urlhaus(domain)
    otx = ti.lookup_otx(domain, indicator_type='domain')
    result = {'indicator': domain, 'case_id': case_id, 'urlhaus': serial(urlhaus), 'otx': serial(otx)}
    get_db()['forensic_artifacts'].insert_one({
        'case_id': case_id, 'type': 'THREAT_INTEL_DOMAIN', 'timestamp': datetime.now(timezone.utc),
        'data': result, 'source': 'THREAT_INTEL',
    })
    log(u, 'THREAT_INTEL_DOMAIN_LOOKUP', 'case', case_id, {'indicator': domain})
    return result
