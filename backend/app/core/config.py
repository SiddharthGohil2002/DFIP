from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator

class Settings(BaseSettings):
    mongodb_uri:str='mongodb://localhost:27017'
    database_name:str='dfip'
    jwt_secret:str='change-me-in-production-use-32-plus-random-bytes'
    access_token_expire_minutes:int=30
    refresh_token_expire_days:int=7
    password_pbkdf2_rounds:int=310000
    storage_path:str='../storage'
    demo_mode:bool=True
    cors_origins:str='http://localhost:5173'
    max_upload_bytes:int=50*1024*1024*1024
    job_poll_seconds:float=1.0
    require_https:bool=False
    redis_url:str='redis://localhost:6379/0'
    celery_task_time_limit:int=1800
    celery_task_soft_time_limit:int=1500
    desktop_job_timeout_minutes:int=60
    virustotal_api_key:str=''
    abuseipdb_api_key:str=''
    otx_api_key:str=''
    model_config=SettingsConfigDict(env_file='.env',extra='ignore',case_sensitive=False)

    @field_validator('jwt_secret')
    @classmethod
    def validate_secret(cls,v):
        return v

settings=Settings()
