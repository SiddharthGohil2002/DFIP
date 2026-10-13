"""The case assistant: a summary built from the case's records (always available, nothing leaves DFIP), and an optional
Claude mode, off for every case until someone who may update the case turns it on, that sends only the summary facts the
investigator selects. Every prompt sent is kept with its answer and recorded in the audit log."""
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..core.config import settings
from ..database import get_db
from ..repositories.cases import get_case
from ..security import current_user, require_write
from ..services.audit import log
from ..services.sequences import next_sequence

r = APIRouter(prefix='/cases', tags=['case assistant'])


class AiSetting(BaseModel):
    enabled: bool


class Ask(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    fact_ids: list[str] = Field(min_length=1, max_length=300)

    @field_validator('question', mode='before')
    @classmethod
    def strip(cls, v):
        return v.strip() if isinstance(v, str) else v


def _case(case_id: str, u) -> dict:
    c = get_case(case_id, u)
    if not c:
        raise HTTPException(404, 'Case not found or access denied')
    return c


def _plain(v):
    if hasattr(v, 'isoformat'):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != '_id'}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


@r.get('/{case_id}/summary')
def summary(case_id: str, u=Depends(current_user)):
    """The case summary: numbered facts in sections, each citing the records it rests on, and paragraphs joining them.
    Built from the stored records alone; the same records always give the same summary."""
    from ..services.case_summary import summary as build
    _case(case_id, u)
    return build(case_id)


@r.get('/{case_id}/ai')
def ai_setting(case_id: str, u=Depends(current_user)):
    from ..services.assistant_llm import configured
    c = _case(case_id, u)
    s = c.get('ai_assist') or {}
    return {'enabled': bool(s.get('enabled')), 'set_by_name': s.get('set_by_name'), 'set_at': _plain(s.get('set_at')), 'configured': configured(),
            'model': settings.anthropic_model}


@r.put('/{case_id}/ai')
def set_ai(case_id: str, x: AiSetting, u=Depends(require_write('CASE_UPDATE'))):
    """Turns the Claude mode on or off for this case (audited). On, investigators may send selected summary facts to Claude."""
    c = _case(case_id, u)
    now = datetime.now(timezone.utc)
    get_db()['cases'].update_one({'case_id': case_id}, {'$set': {'ai_assist': {'enabled': x.enabled, 'set_by': str(u['_id']),
                                                                               'set_by_name': u.get('name'), 'set_at': now}, 'updated_at': now}})
    log(u, 'AI_ASSIST_ENABLED' if x.enabled else 'AI_ASSIST_DISABLED', 'case', c['_id'], {'case_id': case_id})
    return ai_setting(case_id, u)


@r.post('/{case_id}/ai/ask')
def ask(case_id: str, x: Ask, u=Depends(require_write('ANALYSIS_RUN'))):
    """Asks Claude a question about the selected facts of the case summary (and nothing else). The prompt sent, the
    answer and its citations are kept (`ai_requests`) and the request is audited (`AI_PROMPT_SENT`)."""
    from ..services.assistant_llm import AssistantError, ask as send, configured
    from ..services.case_summary import facts as case_facts
    c = _case(case_id, u)
    if not (c.get('ai_assist') or {}).get('enabled'):
        raise HTTPException(409, 'The Claude mode is off for this case')
    if not configured():
        raise HTTPException(503, 'No Anthropic API key is configured on the server (ANTHROPIC_API_KEY)')
    by_id = {f['id']: f for f in case_facts(case_id) if f['id']}
    wanted = list(dict.fromkeys(x.fact_ids))
    unknown = [i for i in wanted if i not in by_id]
    if unknown:
        raise HTTPException(400, f'Not facts of the current summary: {", ".join(unknown[:20])} (the summary may have changed: reload it)')
    selected = [by_id[i] for i in sorted(wanted, key=lambda i: int(i[1:]))]
    db = get_db()
    rid = f'AI-{next_sequence("ai-requests", floor=db["ai_requests"].count_documents({})):05d}'
    now = datetime.now(timezone.utc)
    try:
        result = send(x.question, selected)
    except AssistantError as e:
        db['ai_requests'].insert_one({'ai_request_id': rid, 'case_id': case_id, 'user_id': str(u['_id']), 'user_name': u.get('name'), 'at': now,
                                      'question': x.question, 'fact_ids': [f['id'] for f in selected], 'status': 'FAILED', 'error': str(e),
                                      'model': settings.anthropic_model})
        log(u, 'AI_PROMPT_FAILED', 'case', c['_id'], {'case_id': case_id, 'ai_request_id': rid, 'error': str(e)})
        raise HTTPException(e.status, str(e))
    doc = {'ai_request_id': rid, 'case_id': case_id, 'user_id': str(u['_id']), 'user_name': u.get('name'), 'at': now, 'question': x.question,
           'fact_ids': [f['id'] for f in selected], 'facts': [{'id': f['id'], 'text': f['text'], 'refs': f['refs']} for f in selected],
           'prompt': result['prompt'], 'prompt_sha256': hashlib.sha256(result['prompt'].encode()).hexdigest(), 'status': result['status'],
           'answer': result['answer'], 'citations': result['citations'], 'unknown_citations': result['unknown_citations'], 'model': result['model'],
           'stop_reason': result['stop_reason'], 'refusal_category': result.get('refusal_category'), 'usage': result['usage'],
           'anthropic_message_id': result['request_id']}
    db['ai_requests'].insert_one(doc)
    log(u, 'AI_PROMPT_SENT', 'case', c['_id'], {'case_id': case_id, 'ai_request_id': rid, 'question': x.question, 'fact_ids': doc['fact_ids'],
                                                'prompt_sha256': doc['prompt_sha256'], 'model': doc['model'], 'status': doc['status']})
    return _plain(doc)


@r.get('/{case_id}/ai/requests')
def requests(case_id: str, u=Depends(current_user)):
    """Every question sent to Claude for this case, with what was sent and the answer."""
    _case(case_id, u)
    return {'data': [_plain(x) for x in get_db()['ai_requests'].find({'case_id': case_id}).sort('at', -1).limit(200)]}
