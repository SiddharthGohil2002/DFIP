from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator

# Placeholder secrets shipped in code and .env.example files; never valid outside demo mode.
PLACEHOLDER_SECRETS = {
    'change-me-in-production-use-32-plus-random-bytes',
    'replace-with-a-long-random-secret-at-least-32-characters',
}

class Settings(BaseSettings):
    mongodb_uri:str='mongodb://localhost:27017'
    database_name:str='dfip'
    jwt_secret:str='change-me-in-production-use-32-plus-random-bytes'
    access_token_expire_minutes:int=30
    refresh_token_expire_days:int=7
    password_pbkdf2_rounds:int=310000
    storage_path:str='../storage'
    demo_mode:bool=True
    # Initial ADMIN password when DEMO_MODE is off (min 12 chars). Ignored in demo mode.
    admin_password:str=''
    # When true, mutating endpoints only accept requests from a registered DFIP
    # desktop workstation. When false, the web portal can write too (RBAC still applies).
    require_desktop_for_writes:bool=False
    cors_origins:str='http://localhost:5173'
    max_upload_bytes:int=50*1024*1024*1024
    job_poll_seconds:float=1.0
    require_https:bool=False
    redis_url:str='redis://localhost:6379/0'
    celery_task_time_limit:int=1800
    celery_task_soft_time_limit:int=1500
    # Full disk-image analysis (seconds); real images take far longer than other jobs.
    analysis_time_limit:int=6*3600
    desktop_job_timeout_minutes:int=60
    virustotal_api_key:str=''
    abuseipdb_api_key:str=''
    otx_api_key:str=''
    model_config=SettingsConfigDict(env_file='.env',extra='ignore',case_sensitive=False)

    @model_validator(mode='after')
    def validate_secret(self):
        if not self.demo_mode and (self.jwt_secret in PLACEHOLDER_SECRETS or len(self.jwt_secret) < 32):
            raise ValueError('JWT_SECRET must be a unique random value of at least 32 characters when DEMO_MODE is off')
        return self

settings=Settings()
