import logging
from typing import Optional

logger = logging.getLogger(__name__)


class WireGuardService:
    """Stub for WireGuard control. Replace with real wg set/del logic."""

    def add_peer(self, session_id: str, client_pubkey: str, allowed_ips: str) -> None:
        logger.info("[WG] add peer session=%s pubkey=%s allowed_ips=%s", session_id, client_pubkey, allowed_ips)

    def remove_peer(self, session_id: str, client_pubkey: Optional[str] = None) -> None:
        logger.info("[WG] remove peer session=%s pubkey=%s", session_id, client_pubkey or "?")


wireguard_service = WireGuardService()
