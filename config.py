from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    app_name: str = "DevGuard AI"

    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:7b"

    qdrant_url: str = "http://localhost:6333"
    qdrant_collection: str = "devguard_rules"

    embedding_model: str = "BAAI/bge-small-en-v1.5"

    reranker_model: str = (
        "cross-encoder/ms-marco-MiniLM-L-6-v2"
    )

    top_k: int = 8

    groq_api_key: str | None = None
    groq_model: str = "qwen-2.5-coder-32b"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )


settings = Settings()