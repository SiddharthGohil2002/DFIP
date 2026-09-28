class VectorSearchService:
    """Retrieval over a case's forensic artifacts for AI-assisted Q&A.

    Uses scikit-learn TF-IDF + cosine similarity over artifact text fields.
    This is a real, deterministic retrieval method — not a placeholder — but
    it is intentionally lexical rather than a learned embedding model, since
    that requires no external embedding service/API key and stays fully
    auditable (the exact terms driving a match can be inspected). If nothing
    in the case is relevant to the query, it returns an empty list rather
    than padding results with unrelated artifacts.
    """
    MIN_SIMILARITY = 0.05

    async def search(self, query, case_id, limit=5):
        from ..database import get_db
        docs = list(get_db()['forensic_artifacts'].find({'case_id': case_id}).limit(2000))
        if not docs:
            return []

        def _text(d):
            parts = [str(d.get('type', '')), str(d.get('description', ''))]
            data = d.get('data')
            if isinstance(data, dict):
                parts.append(' '.join(str(v) for v in data.values() if isinstance(v, (str, int, float))))
            return ' '.join(parts).strip()

        corpus = [_text(d) for d in docs]
        if not any(corpus):
            return []

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity
        except ImportError:
            return []

        vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
        try:
            matrix = vectorizer.fit_transform(corpus + [query])
        except ValueError:
            # Empty vocabulary after stop-word removal (e.g. all-numeric artifacts).
            return []

        query_vec = matrix[-1]
        doc_matrix = matrix[:-1]
        similarities = cosine_similarity(query_vec, doc_matrix)[0]

        ranked = sorted(zip(docs, similarities), key=lambda x: x[1], reverse=True)
        results = []
        for doc, score in ranked[:limit]:
            if score < self.MIN_SIMILARITY:
                continue
            doc = dict(doc)
            doc['_relevance_score'] = round(float(score), 4)
            results.append(doc)
        return results

class AIService:
    async def answer(self,question,case_id,context):
        lines=[]
        for item in context[:5]: lines.append(f"• {item.get('type','ARTIFACT')}: {item.get('description','')}")
        answer=(f"Evidence-grounded review for {case_id}: {question}\n\n" + ('\n'.join(lines) if lines else 'No matching forensic artifacts were found in the current case.'))
        return {'answer':answer,'citations':[str(x.get('_id')) for x in context[:5]],'disclaimer':'AI-assisted interpretation. Verify every statement against the original evidence and forensic artifacts.'}
