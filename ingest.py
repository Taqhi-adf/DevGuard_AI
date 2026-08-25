import sys
from pathlib import Path

# Add project root directory to Python path dynamically
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.retrieval import HybridRetriever

if __name__ == "__main__":
    print("🚀 Starting Security Policy Ingestion...")
    retriever = HybridRetriever()
    retriever.ingest()
    print("✅ Security policies successfully indexed.")