import { Fragment, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bot, FileText, Send } from 'lucide-react';
import { api, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useCase } from '../lib/caseContext';
import { useTime } from '../lib/format';
import { useApi } from '../lib/useApi';
import { Badge, Banner, Button, Card, Empty, Field, Loading, PageHeader, useToast } from '../ui';

interface Ref { collection: string; id: string; type?: string; evidence_id?: string }
interface Fact { id: string; section: string; text: string; refs: Ref[] }
interface Summary { generated_at: string; facts: Fact[]; paragraphs: { section: string; title: string; text: string }[]; sections: { section: string; title: string }[] }
interface AiSetting { enabled: boolean; set_by_name?: string; set_at?: string; configured: boolean; model: string }
interface AiRequest {
  ai_request_id: string; user_name: string; at: string; question: string; fact_ids: string[]; status: string; answer: string; citations: string[];
  unknown_citations: string[]; model: string; refusal_category?: string | null; usage?: { input_tokens?: number; output_tokens?: number };
}

const REF_PAGE: [RegExp, string][] = [[/^EVIDENCE$/, '/app/evidence'], [/^USB$/, '/app/usb'], [/^EMAIL$/, '/app/email'], [/^FINDING$/, '/app/findings'],
  [/^(HTTP_REQUEST|DNS_QUERY)$/, '/app/network'], [/^PHONE_/, '/app/phones'], [/^(CLOUD|CHAT)_/, '/app/chat-cloud'], [/^EXECUTABLE|MALWARE_INDICATOR$/, '/app/indicators'],
  [/^(RECYCLE_BIN_ITEM|RECENT_FILE|PROGRAM_RUN)$/, '/app/activity'], [/^(COMPUTER_INFO|USER_ACCOUNT)$/, '/app/computer'], [/^HASH_SET_MATCH$/, '/app/indicators']];
const refPage = (r: Ref) => REF_PAGE.find(([rx]) => rx.test(r.type ?? ''))?.[1] ?? '/app/timeline';

/** Text with [F12] citations turned into buttons that show the fact. */
function Cited({ text, onFact, known }: { text: string; onFact: (id: string) => void; known: Set<string> }) {
  const parts = text.split(/(\[F\d+\])/g);
  return <>{parts.map((p, i) => {
    const m = /^\[(F\d+)\]$/.exec(p);
    if (!m) return <Fragment key={i}>{p}</Fragment>;
    return known.has(m[1]) ? <button key={i} className="link-btn cite" onClick={() => onFact(m[1])} aria-label={`Fact ${m[1]}`}>[{m[1]}]</button>
      : <span key={i} className="mention" title="Not a fact that was sent">[{m[1]}?]</span>;
  })}</>;
}

export function CaseSummaryPage() {
  const { caseId } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const time = useTime();
  const summary = useApi<Summary>(`/cases/${encodeURIComponent(caseId)}/summary`);
  const ai = useApi<AiSetting>(`/cases/${encodeURIComponent(caseId)}/ai`);
  const history = useApi<{ data: AiRequest[] }>(`/cases/${encodeURIComponent(caseId)}/ai/requests`);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [shown, setShown] = useState<string | null>(null);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [answer, setAnswer] = useState<AiRequest | null>(null);
  const facts = summary.data?.facts ?? [];
  const byId = new Map(facts.map((f) => [f.id, f]));
  useEffect(() => { setPicked(new Set()); setAnswer(null); }, [caseId]);

  async function toggleAi() {
    setError('');
    try {
      await api(`/cases/${encodeURIComponent(caseId)}/ai`, { method: 'PUT', json: { enabled: !ai.data?.enabled } });
      ai.reload();
      toast(ai.data?.enabled ? 'Claude mode turned off for this case' : 'Claude mode turned on for this case', 'ok');
    } catch (e: any) { setError(e.message); }
  }
  async function ask() {
    setBusy(true); setError(''); setAnswer(null);
    try {
      const r = await post<AiRequest>(`/cases/${encodeURIComponent(caseId)}/ai/ask`, { question: question.trim(), fact_ids: [...picked] });
      setAnswer(r);
      history.reload();
    } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }
  const sectionFacts = (s: string) => facts.filter((f) => f.section === s);
  const pickSection = (s: string, on: boolean) => {
    const next = new Set(picked);
    sectionFacts(s).forEach((f) => (on ? next.add(f.id) : next.delete(f.id)));
    setPicked(next);
  };
  const fact = shown ? byId.get(shown) : null;
  const known = new Set(facts.map((f) => f.id));

  return (
    <div className="stack">
      <PageHeader title="Case summary"
        subtitle="What the case's records show, as numbered facts that cite the records they come from. Built inside DFIP from the stored records; the same records always give the same summary." />
      {summary.error && <Banner tone="danger">{summary.error}</Banner>}
      {!summary.data ? <Loading /> : !facts.length ? (
        <Card><Empty icon={<FileText size={20} />} title="Nothing to summarise yet" text="Add and analyse evidence; the summary is built from what the analysis finds." /></Card>
      ) : (
        <>
          <Card title="Summary" subtitle={`Built ${time(summary.data.generated_at)}. Select a citation to see the fact and the records behind it.`}>
            {summary.data.paragraphs.map((p) => (
              <div key={p.section} style={{ marginBottom: 12 }}>
                <h4 style={{ margin: '0 0 4px' }}>{p.title}</h4>
                <p className="small" style={{ margin: 0 }}><Cited text={p.text} onFact={setShown} known={known} /></p>
              </div>
            ))}
            {fact && (
              <div className="comment" role="region" aria-label={`Fact ${fact.id}`}>
                <div className="small"><b>{fact.id}</b> {fact.text}</div>
                <div className="tiny">{fact.refs.length ? fact.refs.map((r, i) => <span key={i}>{i > 0 && ', '}<Link to={refPage(r)}>{(r.type ?? r.collection).toLowerCase().replace(/_/g, ' ')}{r.evidence_id ? ` (${r.evidence_id})` : ''}</Link></span>)
                  : <span className="muted">A count over the case; no single record.</span>}</div>
              </div>
            )}
          </Card>

          <Card title="Ask Claude about selected facts"
            subtitle={<>Optional and off by default. When it is on for this case, only the facts you tick are sent to Anthropic ({ai.data?.model ?? 'Claude'}): no files, no other records. Every question, what was sent and the answer are kept and audited.</>}
            actions={can('CASE_UPDATE') && ai.data && <Button size="sm" icon={<Bot size={14} />} onClick={toggleAi}>{ai.data.enabled ? 'Turn off for this case' : 'Turn on for this case'}</Button>}>
            {ai.data && !ai.data.configured && <Banner tone="info">The server has no Anthropic API key (ANTHROPIC_API_KEY), so Claude mode cannot be used.</Banner>}
            {ai.data && !ai.data.enabled ? <p className="small muted" style={{ margin: 0 }}>Claude mode is off for this case{ai.data.set_by_name ? ` (${ai.data.set_by_name}, ${time(ai.data.set_at)})` : ''}.</p> : (
              <>
                <div className="stack" style={{ gap: 8 }}>
                  {summary.data.sections.filter((s) => sectionFacts(s.section).length).map((s) => {
                    const fs = sectionFacts(s.section);
                    const all = fs.every((f) => picked.has(f.id));
                    return (
                      <details key={s.section}>
                        <summary className="small"><label className="check" style={{ display: 'inline-flex' }} onClick={(e) => e.stopPropagation()}>
                          <input type="checkbox" checked={all} onChange={(e) => pickSection(s.section, e.target.checked)} aria-label={`Select all: ${s.title}`} />
                          <b>{s.title}</b></label> <span className="muted">{fs.filter((f) => picked.has(f.id)).length} of {fs.length} selected</span></summary>
                        {fs.map((f) => (
                          <label key={f.id} className="check small" style={{ alignItems: 'flex-start', marginLeft: 22 }}>
                            <input type="checkbox" checked={picked.has(f.id)} onChange={(e) => { const n = new Set(picked); e.target.checked ? n.add(f.id) : n.delete(f.id); setPicked(n); }} />
                            <span><b>{f.id}</b> {f.text}</span>
                          </label>
                        ))}
                      </details>
                    );
                  })}
                </div>
                <Field label="Question">
                  <textarea className="textarea" rows={2} value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="e.g. What happened to the payroll export, in order?" />
                </Field>
                <div className="row between">
                  <span className="small muted">{picked.size} fact{picked.size === 1 ? '' : 's'} will be sent.</span>
                  {can('ANALYSIS_RUN') && <Button variant="primary" icon={<Send size={14} />} busy={busy} disabled={!picked.size || question.trim().length < 3 || !ai.data?.configured} onClick={ask}>Ask Claude</Button>}
                </div>
              </>
            )}
            {error && <Banner tone="danger">{error}</Banner>}
            {answer && <Answer r={answer} onFact={setShown} known={known} />}
          </Card>

          {!!history.data?.data.length && (
            <Card title="Questions asked" subtitle="Every question sent to Claude for this case, with the facts that were sent." flush>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>When</th><th>Who</th><th>Question</th><th>Facts sent</th><th>Status</th></tr></thead>
                  <tbody>
                    {history.data.data.map((h) => (
                      <tr key={h.ai_request_id}>
                        <td className="small nowrap">{time(h.at)}<div className="tiny muted">{h.ai_request_id}</div></td>
                        <td className="small">{h.user_name}</td>
                        <td className="small break">{h.question}<details><summary className="tiny">Answer</summary><div className="small" style={{ whiteSpace: 'pre-wrap' }}>
                          <Cited text={h.answer || '—'} onFact={setShown} known={known} /></div></details></td>
                        <td className="small">{h.fact_ids.join(', ')}</td>
                        <td><Badge tone={h.status === 'ANSWERED' ? 'ok' : h.status === 'FAILED' || h.status === 'REFUSED' ? 'danger' : 'warn'}>{h.status.toLowerCase()}</Badge></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function Answer({ r, onFact, known }: { r: AiRequest; onFact: (id: string) => void; known: Set<string> }) {
  if (r.status === 'REFUSED') return <Banner tone="warn">Claude declined to answer{r.refusal_category ? ` (${r.refusal_category})` : ''}. Rephrase the question or select other facts.</Banner>;
  return (
    <div className="comment" style={{ marginTop: 10 }} aria-label="Claude's answer">
      <div className="tiny muted">{r.ai_request_id} · {r.model}{r.usage?.input_tokens ? ` · ${r.usage.input_tokens.toLocaleString()} tokens in, ${r.usage.output_tokens?.toLocaleString()} out` : ''}</div>
      <div className="small" style={{ whiteSpace: 'pre-wrap' }}><Cited text={r.answer} onFact={onFact} known={new Set([...known].filter((k) => r.fact_ids.includes(k)))} /></div>
      {r.unknown_citations.length > 0 && <div className="tiny" style={{ color: 'var(--danger)' }}>Cites facts that were not sent: {r.unknown_citations.join(', ')}. Treat those statements with care.</div>}
      {r.status === 'TRUNCATED' && <div className="tiny muted">The answer was cut off at its length limit.</div>}
    </div>
  );
}
