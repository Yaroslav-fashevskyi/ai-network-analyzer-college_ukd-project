from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class RagChunk:
    source: str
    text: str
    score: float


class LocalKnowledgeBase:
    """Simple local RAG based on TF-IDF vector search.

    This keeps the project easy to run locally. The vector search is still real:
    documents are chunked, converted into vectors, and ranked by cosine similarity.
    """

    def __init__(self, knowledge_dir: str | Path = "data/knowledge") -> None:
        self.knowledge_dir = Path(knowledge_dir)
        self.documents: list[tuple[str, str]] = []
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
        self.matrix = None
        self._load()

    def _iter_markdown_files(self) -> Iterable[Path]:
        if not self.knowledge_dir.exists():
            return []
        return sorted(self.knowledge_dir.glob("*.md"))

    def _chunk_text(self, source: str, text: str) -> list[tuple[str, str]]:
        blocks = [block.strip() for block in text.split("\n\n") if block.strip()]
        chunks: list[tuple[str, str]] = []
        buffer = ""
        for block in blocks:
            if len(buffer) + len(block) < 900:
                buffer = (buffer + "\n\n" + block).strip()
            else:
                if buffer:
                    chunks.append((source, buffer))
                buffer = block
        if buffer:
            chunks.append((source, buffer))
        return chunks

    def _load(self) -> None:
        self.documents.clear()
        for file in self._iter_markdown_files():
            text = file.read_text(encoding="utf-8")
            self.documents.extend(self._chunk_text(file.name, text))

        if self.documents:
            texts = [text for _, text in self.documents]
            self.matrix = self.vectorizer.fit_transform(texts)
        else:
            self.matrix = None

    def retrieve(self, query: str, k: int = 5) -> list[RagChunk]:
        if not self.documents or self.matrix is None:
            return []
        query_vector = self.vectorizer.transform([query])
        scores = cosine_similarity(query_vector, self.matrix).flatten()
        best_ids = scores.argsort()[::-1][:k]
        chunks: list[RagChunk] = []
        for idx in best_ids:
            score = float(scores[idx])
            if score <= 0:
                continue
            source, text = self.documents[int(idx)]
            chunks.append(RagChunk(source=source, text=text, score=round(score, 4)))
        return chunks
