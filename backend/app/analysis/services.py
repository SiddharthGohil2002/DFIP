from datetime import datetime,timezone

NON_AUTH_TYPES={'FILE_MACB','BROWSER_VISIT','BROWSER_DOWNLOAD','USB_ACTIVITY','PROGRAM_RUN','RECENT_FILE_OPENED','FILE_DELETED_TO_RECYCLE_BIN'}

class PatternService:
    def run(self,events):
        out=[]
        # File, browser and USB events can mention "failed" in a path or URL; only
        # log/authentication-type events count as authentication failures.
        failed=sum(1 for e in events if e.get('type') not in NON_AUTH_TYPES and 'failed' in str(e.get('description','')).lower())
        # Several timeline events describe one device (install, arrival, removal...),
        # so count distinct devices; events without a serial count individually.
        usb_events=[e for e in events if e.get('type')=='USB_ACTIVITY']
        usb=len({e.get('serial') or id(e) for e in usb_events})
        if failed>=3: out.append({'pattern':'Repeated authentication failures','risk':'HIGH','confidence':0.92,'reason':f'{failed} failed authentication events found.'})
        if usb>=2: out.append({'pattern':'Repeated removable-media activity','risk':'MEDIUM','confidence':0.78,'reason':f'{usb} distinct USB devices or events found.'})
        return out

class AnomalyService:
    """Rule-based fallback anomaly scorer. Kept as a fast, dependency-free
    baseline and as the fallback path when there isn't enough data for the
    ML-based detector (see MLAnomalyService) to produce a meaningful result."""
    def run(self,events):
        score=min(100, 20 + sum(15 for e in events if e.get('type') in {'USB_ACTIVITY','FILE_ACCESS'}))
        if not events:return []
        return [{'anomaly_score':score,'risk':'HIGH' if score>=75 else 'MEDIUM' if score>=50 else 'LOW','reason':'Score is based on artifact categories present in the case; investigator review is required.','timestamp':datetime.now(timezone.utc),'method':'RULE_BASED'}]


class MLAnomalyService:
    """Real scikit-learn IsolationForest anomaly detector over per-event
    feature vectors (event type one-hot + hour-of-day + inter-event gap).

    Ground rule: IsolationForest needs a reasonable number of samples to
    produce a meaningful decision boundary. Below MIN_EVENTS, we do not run
    the model and do not fabricate a score — we return an explicit
    'INSUFFICIENT_DATA' status so investigators aren't misled by a confident
    -looking number computed from too little evidence. This mirrors the same
    principle applied everywhere else in DFIP: no invented findings.
    """
    MIN_EVENTS = 15

    def run(self, events):
        if len(events) < self.MIN_EVENTS:
            return {'status': 'INSUFFICIENT_DATA', 'events_available': len(events),
                    'events_required': self.MIN_EVENTS,
                    'detail': 'Not enough timeline events for a statistically meaningful ML anomaly model. '
                              'Falling back to rule-based scoring is recommended (see AnomalyService).'}
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
        except ImportError:
            return {'status': 'ERROR', 'detail': 'scikit-learn is not installed in this environment.'}

        sorted_events = sorted(events, key=lambda e: e.get('timestamp') or datetime.min.replace(tzinfo=timezone.utc))
        event_types = sorted({e.get('type', 'UNKNOWN') for e in sorted_events})
        type_index = {t: i for i, t in enumerate(event_types)}

        rows = []
        prev_ts = None
        for e in sorted_events:
            ts = e.get('timestamp')
            hour = ts.hour if hasattr(ts, 'hour') else 0
            gap_minutes = (ts - prev_ts).total_seconds() / 60.0 if (prev_ts and ts) else 0.0
            one_hot = [0.0] * len(event_types)
            one_hot[type_index.get(e.get('type', 'UNKNOWN'), 0)] = 1.0
            rows.append(one_hot + [float(hour), float(gap_minutes)])
            prev_ts = ts if ts else prev_ts

        X = np.array(rows)
        # contamination='auto' avoids hard-coding an assumed anomaly rate we
        # have no evidentiary basis for.
        model = IsolationForest(n_estimators=200, contamination='auto', random_state=42)
        model.fit(X)
        raw_scores = model.decision_function(X)  # higher = more normal
        predictions = model.predict(X)  # -1 = anomaly, 1 = normal

        # Normalize decision_function output to a 0-100 "anomaly score" for
        # display consistency with the rule-based service, documenting the
        # transform rather than hiding it.
        min_s, max_s = raw_scores.min(), raw_scores.max()
        span = (max_s - min_s) or 1.0

        results = []
        for e, raw, pred in zip(sorted_events, raw_scores, predictions):
            normalized = (max_s - raw) / span * 100.0  # invert: higher raw (more normal) -> lower score
            results.append({
                'event_type': e.get('type'), 'timestamp': e.get('timestamp'),
                'anomaly_score': round(float(normalized), 2),
                'is_anomaly': bool(pred == -1),
                'method': 'ISOLATION_FOREST',
            })
        anomalous = [r for r in results if r['is_anomaly']]
        return {
            'status': 'COMPLETED', 'method': 'ISOLATION_FOREST', 'events_analyzed': len(events),
            'anomalies_detected': len(anomalous),
            'reason': 'Scores reflect statistical isolation within this case\'s own event distribution only; '
                      'investigator review is required before treating any flagged event as confirmed malicious.',
            'results': sorted(results, key=lambda r: r['anomaly_score'], reverse=True)[:200],
        }



# Upper bound on events loaded for case analytics; filesystem timelines of real
# disks run to hundreds of thousands of events.
MAX_ANALYTIC_EVENTS = 50_000


def _case_events(db, case_id):
    return list(db['timeline_events'].find({'case_id': case_id}, {'_id': 0}).sort('timestamp', -1).limit(MAX_ANALYTIC_EVENTS))


def compute_patterns(db, case_id):
    """Recomputes and stores pattern results for a case; returns the stored docs."""
    now = datetime.now(timezone.utc)
    docs = [dict(x, case_id=case_id, created_at=now) for x in PatternService().run(_case_events(db, case_id))]
    db['patterns'].delete_many({'case_id': case_id})
    if docs:
        db['patterns'].insert_many(docs)
    return docs


def compute_anomalies(db, case_id):
    """Recomputes and stores anomaly results for a case. Uses IsolationForest when
    there is enough data, otherwise the rule-based scorer (reported as such)."""
    events = _case_events(db, case_id)
    ml_result = MLAnomalyService().run(events)
    if ml_result.get('status') == 'COMPLETED':
        results, method = ml_result['results'], 'ISOLATION_FOREST'
        extra = {'ml_summary': {k: v for k, v in ml_result.items() if k != 'results'}}
    else:
        results, method = AnomalyService().run(events), 'RULE_BASED_FALLBACK'
        extra = {'ml_status': ml_result}
    now = datetime.now(timezone.utc)
    docs = [dict(x, case_id=case_id, created_at=now, detection_method=method) for x in results]
    db['anomalies'].delete_many({'case_id': case_id})
    if docs:
        db['anomalies'].insert_many(docs)
    return docs, method, extra
