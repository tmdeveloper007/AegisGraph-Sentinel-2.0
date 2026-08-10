
MFA verification module with proper TOTP token validation.
"""
import hmac
import hashlib
import time
import logging

logger = logging.getLogger(__name__)

TOTP_STEP = 30

try:
    import pyotp
    _HAS_PYOTP = True
except ImportError:
    _HAS_PYOTP = False
    logger.warning("pyotp not available; using format-only validation")


def verify_mtp_token(user_id: str, token: str) -> bool:
    """Verify an MFA token for a user using TOTP.

    Args:
        user_id: The user identifier.
        token: The OTP token to verify (typically 6-8 digits).

    Returns:
        True if the token is valid, False otherwise.
    """
    if not token or not isinstance(token, str):
        return False

    token = token.strip()

    if not token.isdigit() or len(token) < 6 or len(token) > 8:
        logger.warning(f"Invalid MFA token format for user {user_id}")
        return False

    user_secret = _get_user_totp_secret(user_id)
    if user_secret is None:
        logger.warning(f"No MFA secret registered for user {user_id}")
        return False

    if _HAS_PYOTP:
        try:
            totp = pyotp.TOTP(user_secret)
            valid = totp.verify(token, valid_window=1)
            logger.info(f"MFA token verified for user {user_id}: {valid}")
            return valid
        except Exception as exc:
            logger.error(f"MFA verification error for user {user_id}: {exc}")
            return False
    else:
        expected = _generate_fallback_otp(user_secret, len(token))
        result = hmac.compare_digest(token, expected)
        logger.info(f"MFA token verified (fallback) for user {user_id}: {result}")
        return result


def verify_mfa_token(user_id: str, token: str) -> bool:
    """Verify an MFA token for a user.

    Args:
        user_id: The user identifier.
        token: The OTP token to verify (typically 6-8 digits).

    Returns:
        True if the token is valid, False otherwise.
    """
    return verify_mtp_token(user_id, token)


def _get_user_totp_secret(user_id: str) -> str | None:
    """Retrieve the TOTP secret for a user from the auth store.

    In production, replace with: return auth_store.get_totp_secret(user_id)
    """
    return None


def _generate_fallback_otp(secret: str, digits: int) -> str:
    """Generate a deterministic fallback OTP using HMAC-SHA1 over the current time step."""
    time_step = int(time.time()) // TOTP_STEP
    hmac_obj = hmac.new(secret.encode(), str(time_step).encode(), hashlib.sha1)
    digest = hmac_obj.hexdigest()
    return str(int(digest[:8], 16) % (10 ** digits)).zfill(digits)

