from pathlib import Path
import os

from qdrant_client import QdrantClient
from qdrant_client.models import (
    VectorParams,
    Distance,
    PointStruct
)

from sentence_transformers import (
    SentenceTransformer,
    CrossEncoder
)

from rank_bm25 import BM25Okapi

from app.config import settings


class HybridRetriever:

    def __init__(self):
        print("🔄 Initializing Embedding model and Reranker...")
        self.embedder = SentenceTransformer(
            settings.embedding_model
        )

        self.reranker = CrossEncoder(
            settings.reranker_model
        )

        self.client = QdrantClient(
            url=settings.qdrant_url
        )

        self.documents = []
        self.bm25 = None

    def load_documents(self):
        self.documents = []
        directory = Path("data/security_rules")

        # Create directory and sample rules if missing
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            sample_rule = directory / "owasp_top_10.md"
            sample_rule.write_text(
                "# Security Rule: Prevent SQL Injection\n\n"
                "Never concatenate raw user input into dynamic SQL strings. Always use parameterized queries.\n\n"
                "# Security Rule: Prevent Hardcoded Secrets\n\n"
                "Never store secrets, API keys, or database credentials directly in source code.",
                encoding="utf-8"
            )

        markdown_files = list(directory.glob("*.md"))
        if not markdown_files:
            print(f"⚠️ No markdown files found in {directory}. Creating a default policy file...")
            sample_rule = directory / "owasp_top_10.md"
            sample_rule.write_text(
                "# Security Rule: Prevent SQL Injection\n\n"
                "Never concatenate raw user input into dynamic SQL strings. Always use parameterized queries.",
                encoding="utf-8"
            )
            markdown_files = [sample_rule]

        for file in markdown_files:
            text = file.read_text(encoding="utf-8")

            blocks = [
                block.strip()
                for block in text.split("\n\n")
                if block.strip()
            ]

            for index, block in enumerate(blocks):
                self.documents.append({
                    "id": f"{file.stem}-{index}",
                    "text": block,
                    "source": file.name
                })

        corpus = [
            doc["text"].lower().split()
            for doc in self.documents
        ]

        if corpus:
            self.bm25 = BM25Okapi(corpus)

    def create_collection(self):
        dimension = (
            self.embedder.get_sentence_embedding_dimension()
        )

        existing = {
            c.name
            for c in self.client.get_collections().collections
        }

        if settings.qdrant_collection not in existing:
            print(f"📦 Creating Qdrant collection: {settings.qdrant_collection}")
            self.client.create_collection(
                collection_name=settings.qdrant_collection,
                vectors_config=VectorParams(
                    size=dimension,
                    distance=Distance.COSINE
                )
            )

    def ingest(self):
        print("📄 Loading documents...")
        self.load_documents()

        print("⚡ Setting up Qdrant vector database...")
        self.create_collection()

        if not self.documents:
            print("⚠️ No documents available to ingest.")
            return

        print(f"🧠 Generating embeddings for {len(self.documents)} text blocks...")
        embeddings = self.embedder.encode(
            [d["text"] for d in self.documents],
            normalize_embeddings=True
        )

        points = []
        for index, (doc, vector) in enumerate(zip(self.documents, embeddings)):
            points.append(
                PointStruct(
                    id=index,
                    vector=vector.tolist(),
                    payload=doc
                )
            )

        print("💾 Upserting vectors into Qdrant...")
        self.client.upsert(
            collection_name=settings.qdrant_collection,
            points=points
        )

    def search(self, query: str):
        query_vector = (
            self.embedder.encode(
                query,
                normalize_embeddings=True
            ).tolist()
        )

        dense_results = (
            self.client.query_points(
                collection_name=settings.qdrant_collection,
                query=query_vector,
                limit=8,
                with_payload=True
            ).points
        )

        candidates = {}

        for result in dense_results:
            payload = result.payload
            candidates[payload["id"]] = payload

        if self.bm25:
            scores = self.bm25.get_scores(
                query.lower().split()
            )

            for index in scores.argsort()[-8:][::-1]:
                if int(index) < len(self.documents):
                    document = self.documents[int(index)]
                    candidates[document["id"]] = document

        candidate_list = list(candidates.values())

        if not candidate_list:
            return []

        pairs = [
            (query, item["text"])
            for item in candidate_list
        ]

        scores = self.reranker.predict(pairs)

        for item, score in zip(candidate_list, scores):
            item["rerank_score"] = float(score)

        return sorted(
            candidate_list,
            key=lambda x: x["rerank_score"],
            reverse=True
        )[:5]