from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="/home/krishna/threatvision/.env", extra="ignore")

    # App
    app_name: str = "ThreatVision"
    debug: bool = False
    version: str = "0.1.0"

    # Anthropic
    anthropic_api_key: str = ""

    # Database
    postgres_url: str = "postgresql+asyncpg://threatvision:threatvision@localhost:5432/threatvision"
    postgres_url_sync: str = "postgresql://threatvision:threatvision@localhost:5432/threatvision"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8001

    # Auth
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # CORS
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
