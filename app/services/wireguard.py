import logging
import os

import httpx
from app.config import settings

logger = logging.getLogger(__name__)


_client = httpx.Client(
    transport=httpx.HTTPTransport(uds=settings.wgctl_socket),
    base_url="http://wgctl",
    timeout=5.0,
)


class WireGuardService:
    """WireGuard control via wg-daemon (unix socket)."""

    def add_peer(self, session_id: str, client_pubkey: str, allowed_ips: str) -> None:
        logger.info("[WG] add peer session=%s pubkey=%s allowed_ips=%s",
                    session_id, client_pubkey, allowed_ips)
        try:
            r = _client.post(
                "/peer/add",
                json={"pubkey": client_pubkey, "allowed_ips": allowed_ips},
                headers={"X-WGCTL-Token": settings.wgctl_token},
            )
            r.raise_for_status()
            action = r.json().get("action")
            logger.info("[WG] add peer OK session=%s pubkey=%s action=%s",
                        session_id, client_pubkey, action)
        except httpx.HTTPStatusError as e:
            body = getattr(e.response, "text", "")
            logger.error("[WG] add peer FAILED session=%s pubkey=%s status=%s body=%r",
                         session_id, client_pubkey,
                         e.response.status_code if e.response else None, body)
            raise
        except Exception as e:
            logger.exception("[WG] add peer ERROR session=%s pubkey=%s err=%r",
                             session_id, client_pubkey, e)
            raise

    def remove_peer(self, session_id: str, client_pubkey: str) -> None:
        logger.info("[WG] remove peer session=%s pubkey=%s",
                    session_id, client_pubkey)
        try:
            r = _client.post(
                "/peer/remove",
                json={"pubkey": client_pubkey},
                headers={"X-WGCTL-Token": settings.wgctl_token},
            )
            r.raise_for_status()
            action = r.json().get("action")
            logger.info("[WG] remove peer OK session=%s pubkey=%s action=%s",
                        session_id, client_pubkey, action)
        except httpx.HTTPStatusError as e:
            body = getattr(e.response, "text", "")
            logger.error("[WG] remove peer FAILED session=%s pubkey=%s status=%s body=%r",
                         session_id, client_pubkey,
                         e.response.status_code if e.response else None, body)
            raise
        except Exception as e:
            logger.exception("[WG] remove peer ERROR session=%s pubkey=%s err=%r",
                             session_id, client_pubkey, e)
            raise

wireguard_service = WireGuardService()
