from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_DETAILS: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_DB: int
    EXCHANGE_RATE_API_KEY: str

    class Config:
        env_file = ".env"

settings = Settings()