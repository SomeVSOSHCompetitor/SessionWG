from datetime import timedelta
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WG_", env_file=".env", env_file_encoding="utf-8")

    # Core
    project_name: str = "wireguard-session-service"
    environment: str = "dev"

    seed_default_user: bool = False

    # Security
    jwt_secret_key: str = "change-me"
    jwt_algorithm: str = "HS256"
    access_token_expires_seconds: int = 900
    proof_token_expires_seconds: int = 60

    # Session control
    ttl_max_seconds: int = 8 * 60 * 60  # 8 hours default
    ttl_step_default_seconds: int = 15 * 60
    allow_multiple_active_sessions: bool = False

    # Database
    # Example: postgresql+psycopg2://user:pass@localhost:5432/dbname
    database_url: str = "postgresql+psycopg2://postgres:password@localhost:5432/wg"

    # WireGuard defaults
    interface: str = "wg0"
    endpoint: str = "vpn.example.com:51820"
    gateway_pubkey: str = "GATEWAY_PUBKEY_PLACEHOLDER"
    allowed_ips: list[str] = []
    reserved_ips: list[str] = []
    dns: str = "10.0.0.1"
    network_cidr: str = "10.0.0.0/24"

    # IP Quarantine
    ip_quarantine_duration_seconds: int = 180

    # wgctl settings
    wgctl_token: str = "secret-token-change-me"
    wgctl_socket: str = "/run/wgctl/wgctl.sock"

    # Admin
    admin_token: str = "admin-token-change-me"

    def access_token_ttl(self) -> timedelta:
        return timedelta(seconds=self.access_token_expires_seconds)

    def proof_token_ttl(self) -> timedelta:
        return timedelta(seconds=self.proof_token_expires_seconds)




settings = Settings()
