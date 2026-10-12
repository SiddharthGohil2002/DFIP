"""Threat intelligence connectors.

Ground rule: a threat-intel lookup either returns a real response from the
provider, a real cached copy of one, or an honest NOT_CONFIGURED / ERROR
status. It never fabricates a verdict, reputation score, or "clean" result
when a key is missing or a request fails — a fabricated "clean" verdict would
be actively dangerous in casework (worse than no data at all).

Every result is stored with its provider, raw response, and query timestamp so
an investigator (or a court) can independently verify provenance later,
consistent with the rest of DFIP's evidence-handling rules.
"""
from __future__ import annotations
import httpx
from datetime import datetime, timezone
from ..core.config import settings
from ..database import get_db

CACHE_COLLECTION = 'threat_intel_cache'


def _cache_key(provider: str, indicator: str) -> str:
    return f'{provider}:{indicator.strip().lower()}'


def _get_cached(provider: str, indicator: str, max_age_seconds: int):
    doc = get_db()[CACHE_COLLECTION].find_one({'_id': _cache_key(provider, indicator)})
    if not doc:
        return None
    age = (datetime.now(timezone.utc) - doc['queried_at'].replace(tzinfo=timezone.utc)).total_seconds()
    if age > max_age_seconds:
        return None
    doc['from_cache'] = True
    return doc


def _store_cache(provider: str, indicator: str, response: dict):
    now = datetime.now(timezone.utc)
    doc = {'_id': _cache_key(provider, indicator), 'provider': provider, 'indicator': indicator,
           'queried_at': now, **response}
    get_db()[CACHE_COLLECTION].replace_one({'_id': doc['_id']}, doc, upsert=True)
    return doc


def _not_configured(provider: str, indicator: str) -> dict:
    return {'provider': provider, 'indicator': indicator, 'status': 'NOT_CONFIGURED',
            'detail': f'No API key configured for {provider}. Set the relevant environment variable to enable real lookups.'}


def lookup_virustotal_hash(file_hash: str, max_age_seconds: int = 3600, peek: bool = False) -> dict | None:
    """A file hash on VirusTotal (only the hash is sent). peek=True returns a cached answer or None, without a request."""
    provider = 'VIRUSTOTAL'
    if not settings.virustotal_api_key:
        return _not_configured(provider, file_hash)
    cached = _get_cached(provider, file_hash, max_age_seconds)
    if cached:
        return cached
    if peek:
        return None
    try:
        resp = httpx.get(
            f'{settings.virustotal_base_url.rstrip("/")}/files/{file_hash}',
            headers={'x-apikey': settings.virustotal_api_key}, timeout=20,
        )
        if resp.status_code == 404:
            result = {'status': 'NOT_FOUND', 'raw': None}
        elif resp.status_code == 200:
            data = resp.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            result = {'status': 'COMPLETED', 'malicious': stats.get('malicious', 0),
                      'suspicious': stats.get('suspicious', 0), 'harmless': stats.get('harmless', 0),
                      'undetected': stats.get('undetected', 0), 'raw': data}
        else:
            result = {'status': 'ERROR', 'http_status': resp.status_code, 'raw': resp.text[:2000]}
    except httpx.HTTPError as exc:
        result = {'status': 'ERROR', 'error': str(exc)}
    return _store_cache(provider, file_hash, result)


def lookup_abuseipdb(ip_address: str, max_age_seconds: int = 3600) -> dict:
    provider = 'ABUSEIPDB'
    if not settings.abuseipdb_api_key:
        return _not_configured(provider, ip_address)
    cached = _get_cached(provider, ip_address, max_age_seconds)
    if cached:
        return cached
    try:
        resp = httpx.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip_address, 'maxAgeInDays': 90},
            headers={'Key': settings.abuseipdb_api_key, 'Accept': 'application/json'}, timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            result = {'status': 'COMPLETED', 'abuse_confidence_score': data.get('abuseConfidenceScore'),
                      'total_reports': data.get('totalReports'), 'country_code': data.get('countryCode'),
                      'is_public': data.get('isPublic'), 'raw': data}
        else:
            result = {'status': 'ERROR', 'http_status': resp.status_code, 'raw': resp.text[:2000]}
    except httpx.HTTPError as exc:
        result = {'status': 'ERROR', 'error': str(exc)}
    return _store_cache(provider, ip_address, result)


def lookup_otx(indicator: str, indicator_type: str = 'IPv4', max_age_seconds: int = 3600) -> dict:
    """AlienVault OTX. indicator_type follows OTX's own path segments:
    IPv4, IPv6, domain, hostname, file (hash), url."""
    provider = 'OTX'
    if not settings.otx_api_key:
        return _not_configured(provider, indicator)
    cached = _get_cached(provider, indicator, max_age_seconds)
    if cached:
        return cached
    try:
        resp = httpx.get(
            f'https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general',
            headers={'X-OTX-API-KEY': settings.otx_api_key}, timeout=20,
        )
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get('pulse_info', {}).get('pulses', [])
            result = {'status': 'COMPLETED', 'pulse_count': len(pulses),
                      'pulse_names': [p.get('name') for p in pulses[:20]], 'raw': data}
        elif resp.status_code == 404:
            result = {'status': 'NOT_FOUND', 'raw': None}
        else:
            result = {'status': 'ERROR', 'http_status': resp.status_code, 'raw': resp.text[:2000]}
    except httpx.HTTPError as exc:
        result = {'status': 'ERROR', 'error': str(exc)}
    return _store_cache(provider, indicator, result)


def lookup_urlhaus(url_or_host: str, max_age_seconds: int = 3600) -> dict:
    """URLhaus host lookup. abuse.ch requires an Auth-Key for API queries
    (URLHAUS_API_KEY); without one nothing is sent."""
    provider = 'URLHAUS'
    if not settings.urlhaus_api_key:
        return _not_configured(provider, url_or_host)
    cached = _get_cached(provider, url_or_host, max_age_seconds)
    if cached:
        return cached
    try:
        resp = httpx.post(
            'https://urlhaus-api.abuse.ch/v1/host/', data={'host': url_or_host}, timeout=20,
            headers={'Auth-Key': settings.urlhaus_api_key},
        )
        if resp.status_code == 200:
            data = resp.json()
            query_status = data.get('query_status')
            if query_status == 'ok':
                urls = data.get('urls', [])
                result = {'status': 'COMPLETED', 'url_count': len(urls),
                          'urls': [{'url': u.get('url'), 'threat': u.get('threat'), 'status': u.get('url_status')}
                                   for u in urls[:50]], 'raw': data}
            elif query_status == 'no_results':
                result = {'status': 'NOT_FOUND', 'raw': data}
            else:
                result = {'status': 'ERROR', 'detail': query_status, 'raw': data}
        else:
            result = {'status': 'ERROR', 'http_status': resp.status_code, 'raw': resp.text[:2000]}
    except httpx.HTTPError as exc:
        result = {'status': 'ERROR', 'error': str(exc)}
    return _store_cache(provider, url_or_host, result)


PROVIDERS = {
    'virustotal_hash': lookup_virustotal_hash,
    'abuseipdb': lookup_abuseipdb,
    'otx': lookup_otx,
    'urlhaus': lookup_urlhaus,
}
