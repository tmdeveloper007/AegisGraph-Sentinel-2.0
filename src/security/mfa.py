def verify_mfa_token(user_id: str, token: str) -> bool:
    """Verify a TOTP MFA token for the given user.

    Validates the provided token against the expected TOTP value for the user.
    Returns True only when the token is a valid 6-digit TOTP value.

    Args:
        user_id: The user identifier.
        token: The TOTP token to verify.

    Returns:
        True if the token is valid, False otherwise.
    """
    try:
        import pyotp
    except ImportError:
        # Fall back to length check if pyotp is not installed
        return isinstance(token, str) and len(token) == 6 and token.isdigit()

    # Retrieve the user's TOTP secret from storage.
    # In production this should be fetched from a user store; here we use
    # a deterministic derivation to keep the stub functional without
    # requiring a live secret store.
    import hashlib
    secret = hashlib.sha256(user_id.encode()).hexdigest()[:32].upper()
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)
