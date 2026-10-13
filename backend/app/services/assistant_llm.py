"""The Claude mode of the case assistant: a question answered by Claude from facts of the case summary that the
investigator selected, and only those (no files, no raw records). The answer must cite the facts it uses ([F3]);
citations of facts that were not sent are reported. Off for every case until turned on for that case."""
from __future__ import annotations
import re

import anthropic

from ..core.config import settings

SYSTEM = ('You help a digital forensic investigator understand a case. The user message gives numbered facts taken from the '
          "case's records (F1, F2 ...) and a question. Answer using only those facts. After each statement, cite the facts it "
          'rests on in square brackets, like [F3] or [F2][F5]. If the facts do not answer the question, say so plainly and say '
          'what kind of record would. Describe what the records show; do not speculate about intent or guilt. Be brief and precise.')
CITE = re.compile(r'\[(F\d+)\]')


class AssistantError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def configured() -> bool:
    return bool(settings.anthropic_api_key)


def prompt(question: str, facts: list[dict]) -> str:
    return 'Facts:\n' + '\n'.join(f'[{f["id"]}] {f["text"]}' for f in facts) + f'\n\nQuestion: {question.strip()}'


def ask(question: str, facts: list[dict]) -> dict:
    """Sends the selected facts and the question to Claude; returns the answer with its citations."""
    if not configured():
        raise AssistantError(503, 'No Anthropic API key is configured on the server (ANTHROPIC_API_KEY)')
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key, base_url=settings.anthropic_base_url or None, timeout=180.0, max_retries=2)
    user = prompt(question, facts)
    try:
        resp = client.beta.messages.create(
            model=settings.anthropic_model, max_tokens=16000, system=SYSTEM,
            messages=[{'role': 'user', 'content': user}],
            output_config={'effort': 'medium'},
            # A request a safety classifier declines is re-run server-side on the model Anthropic recommends for that category.
            betas=['server-side-fallback-2026-07-01'], fallbacks='default',
        )
    except anthropic.AuthenticationError:
        raise AssistantError(502, 'The Anthropic API rejected the server\'s API key')
    except anthropic.PermissionDeniedError:
        raise AssistantError(502, 'The server\'s API key may not use this model')
    except anthropic.RateLimitError:
        raise AssistantError(503, 'The Anthropic API is rate limiting requests; try again shortly')
    except anthropic.BadRequestError as e:
        raise AssistantError(502, f'The Anthropic API refused the request: {e.message}')
    except anthropic.APIStatusError as e:
        raise AssistantError(502 if e.status_code < 500 else 503, f'The Anthropic API answered {e.status_code}')
    except anthropic.APIConnectionError:
        raise AssistantError(503, 'The Anthropic API could not be reached')
    sent = {f['id'] for f in facts}
    if resp.stop_reason == 'refusal':
        details = getattr(resp, 'stop_details', None)
        return {'status': 'REFUSED', 'answer': '', 'citations': [], 'unknown_citations': [], 'model': resp.model, 'stop_reason': resp.stop_reason,
                'refusal_category': getattr(details, 'category', None), 'usage': _usage(resp), 'prompt': user, 'request_id': resp.id}
    text = ''.join(b.text for b in resp.content if b.type == 'text').strip()
    cited = list(dict.fromkeys(CITE.findall(text)))
    return {'status': 'ANSWERED' if resp.stop_reason != 'max_tokens' else 'TRUNCATED', 'answer': text,
            'citations': [c for c in cited if c in sent], 'unknown_citations': [c for c in cited if c not in sent],
            'model': resp.model, 'stop_reason': resp.stop_reason, 'usage': _usage(resp), 'prompt': user, 'request_id': resp.id}


def _usage(resp) -> dict:
    u = getattr(resp, 'usage', None)
    return {'input_tokens': getattr(u, 'input_tokens', None), 'output_tokens': getattr(u, 'output_tokens', None)}
