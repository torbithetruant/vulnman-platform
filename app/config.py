from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str  
    redis_url: str = "redis://redis:6379/0" 
    secret_key: str  
    webhook_secret: str = "change-me-in-production"
    
    # JWT Settings
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()