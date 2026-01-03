import logging
import subprocess
from app.config import settings

logger = logging.getLogger(__name__)


class WireGuardService:
    """Stub for WireGuard control. Replace with real wg set/del logic."""

    def add_peer(self, session_id: str, client_pubkey: str, allowed_ips: str) -> None:
        logger.info("[WG] add peer session=%s pubkey=%s allowed_ips=%s", session_id, client_pubkey, allowed_ips)

    def remove_peer(self, session_id: str, client_pubkey: str) -> None:
        iface = settings.interface
        cmd = ["wg", "set", iface, "peer", client_pubkey, "remove"]

        logger.info("[WG] remove peer session=%s pubkey=%s", session_id, client_pubkey)
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            stdout = (e.stdout or "").strip()

            # Идемпотентность: если peer уже отсутствует — считаем успехом.
            # wg обычно пишет в stderr что-то вроде "Unable to find peer ..."
            msg = (stderr or stdout).lower()
            if "unable to find peer" in msg or "no such" in msg or "not found" in msg:
                logger.warning("[WG] peer already absent session=%s pubkey=%s", session_id, client_pubkey)
                return

            logger.error("[WG] remove failed session=%s pubkey=%s stderr=%r stdout=%r",
                         session_id, client_pubkey, stderr, stdout)
            raise

wireguard_service = WireGuardService()
