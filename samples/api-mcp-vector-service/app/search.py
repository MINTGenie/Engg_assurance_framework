"""Vector search helpers (fixture with planted defects)."""
from langchain_community.embeddings import FakeEmbeddings
from langchain_community.vectorstores import FAISS
from qdrant_client import QdrantClient

# planted: plain-http connection to a remote vector database
client = QdrantClient(url="http://qdrant.fleet.example:6333")


def load_index(path: str):
    # planted: pickle-based index loading
    return FAISS.load_local(path, FakeEmbeddings(size=8), allow_dangerous_deserialization=True)


def search(query_vector: list[float], limit: int = 5):
    return client.search(collection_name="documents", query_vector=query_vector, limit=limit)
