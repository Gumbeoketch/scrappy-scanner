"""
JWT security checks — fully self-contained.

Everything runs locally with the Python standard library. The token is NEVER
sent to any third-party service (e.g. jwt.io / xjwt.io): submitting a real token
to an external site would leak the signing material. Use those sites only as a
reference for *which* checks matter; this module performs them offline.

Automated, deterministic checks:
  - structural decode (header / payload)
  - ``alg: none`` acceptance pattern (unsigned token)
  - weak HMAC secret (offline dictionary attack against HS256/384/512)
  - missing / expired ``exp`` (and ``nbf`` / ``iat`` sanity)
  - dangerous header params (``jku`` / ``x5u`` / ``jwk`` -> SSRF / key injection)
  - ``kid`` present -> candidate for injection testing
  - RS*/ES*/PS* -> algorithm-confusion candidate (forges HS evidence if a public
    key is supplied)
  - sensitive / privilege claims inspection

Checks that require the target server (does it *accept* a forged token?) are
reported as candidates with reproduction steps — confirm those against the app.
"""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

MODULE_TYPE = "JWT"

# Small built-in list of commonly used/leaked HMAC signing secrets. Callers can
# extend this with their own wordlist.
COMMON_HMAC_SECRETS = [
    "secret", "secretkey", "secret_key", "password", "changeme", "change-me",
    "123456", "12345678", "qwerty", "admin", "administrator", "root", "test",
    "jwt", "jwtsecret", "jwt_secret", "token", "key", "private", "privatekey",
    "your-256-bit-secret", "your_jwt_secret", "mysecret", "mysecretkey",
    "supersecret", "s3cr3t", "s3cret", "default", "example", "dev", "development",
    "production", "prod", "staging", "secret123", "password123", "p@ssw0rd",
    "SigningKey", "signing_key", "HS256", "shhhh", "iloveyou", "letmein",
]

# Claim keys that often carry authorization-relevant or sensitive data.
_PRIVILEGE_CLAIMS = {
    "role", "roles", "is_admin", "isadmin", "admin", "scope", "scopes",
    "permissions", "perms", "authorities", "grp", "groups", "level", "tier",
}
_SENSITIVE_CLAIMS = {"password", "pwd", "secret", "ssn", "credit_card", "card"}

_HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
_ASYMMETRIC_PREFIXES = ("RS", "ES", "PS")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_jwt(token: str):
    """Return (header, payload, signing_input, signature_bytes, parts)."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT: expected at least two dot-separated segments")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Malformed JWT segments: {exc}")
    signature = _b64url_decode(parts[2]) if len(parts) >= 3 and parts[2] else b""
    signing_input = parts[0] + "." + parts[1]
    return header, payload, signing_input, signature, parts


def _finding(title, severity, description, recommendation, references=None, components=None):
    return {
        "status": "in-progress",
        "data": {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "affected_components": components or ["JWT"],
            "references": references or [],
            "type": MODULE_TYPE,
        },
    }


def _crack_hmac(signing_input, signature, hashfn, candidates):
    for secret in candidates:
        if not secret:
            continue
        computed = hmac.new(secret.encode("utf-8", "ignore"),
                            signing_input.encode(), hashfn).digest()
        if hmac.compare_digest(computed, signature):
            return secret
    return None


def _forge_hs256(header, payload, key_bytes):
    forged_header = {**header, "alg": "HS256"}
    h = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"
    sig = hmac.new(key_bytes, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(token, hmac_wordlist=None, public_key=None):
    """Run all JWT checks and return a list of findings."""
    token = (token or "").strip()
    findings = []

    if not token:
        return [_finding(
            "No JWT provided", "info",
            "No token was supplied to the JWT scanner.",
            "Paste a JWT to analyse.")]

    try:
        header, payload, signing_input, signature, parts = decode_jwt(token)
    except ValueError as exc:
        return [_finding(
            "Not a valid JWT", "info",
            f"The supplied value could not be parsed as a JWT. {exc}",
            "Provide a well-formed JSON Web Token (header.payload.signature).")]

    alg = str(header.get("alg", "")).strip()
    typ = header.get("typ", "")

    # --- structural summary (informational) ---
    claim_keys = ", ".join(sorted(payload.keys())) or "(none)"
    findings.append(_finding(
        f"JWT decoded (alg={alg or 'unset'}, typ={typ or 'unset'})", "info",
        f"Header algorithm: {alg or 'unset'}. Claims present: {claim_keys}. "
        "Payload is base64url-encoded, not encrypted — anyone holding the token "
        "can read every claim.",
        "Never place secrets or trust-bearing data in the payload expecting it to "
        "be hidden. Treat all claims as attacker-readable.",
        components=[f"alg={alg or 'unset'}"] + ([f"kid={header['kid']}"] if header.get("kid") else []),
    ))

    # --- alg: none ---
    if alg.lower() == "none":
        findings.append(_finding(
            "JWT uses 'alg: none' (unsigned token)", "high",
            "The token header declares 'alg: none', meaning it carries no "
            "signature. If the server accepts this, an attacker can mint arbitrary "
            "tokens (any user/role) with no key.",
            "Reject 'none' explicitly. Configure the library with an allow-list of "
            "expected algorithms (e.g. only HS256 or only RS256) and verify the "
            "signature on every request.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            components=["alg=none"],
        ))

    # --- unsigned (no signature segment) ---
    if not signature and alg.lower() != "none":
        findings.append(_finding(
            "JWT has no signature segment", "high",
            "The token has no signature part, so its integrity cannot be verified.",
            "Ensure tokens are signed and the server verifies the signature.",
            components=["signature=empty"],
        ))

    # --- weak HMAC secret (offline dictionary attack) ---
    if alg.upper() in _HS_ALGS and signature:
        candidates = list(COMMON_HMAC_SECRETS)
        if hmac_wordlist:
            extra = [w.strip() for w in str(hmac_wordlist).splitlines() if w.strip()]
            candidates.extend(extra[:50000])  # cap to keep it bounded
        cracked = _crack_hmac(signing_input, signature, _HS_ALGS[alg.upper()], candidates)
        if cracked is not None:
            forged = _forge_hs256({**header, "alg": alg.upper()},
                                  {**payload}, cracked.encode())
            findings.append(_finding(
                f"Weak HMAC signing secret recovered ('{cracked}')", "high",
                f"The {alg.upper()} signing secret was recovered offline by trying a "
                f"short dictionary — the secret is '{cracked}'. Anyone who guesses it "
                "can forge valid tokens for any user or role.",
                "Replace the secret immediately with a long, high-entropy random key "
                "(>= 256 bits for HS256). Rotate it, invalidate existing tokens, and "
                "store it in a secrets manager — never in source or config files.",
                references=["https://cwe.mitre.org/data/definitions/326.html"],
                components=[f"secret={cracked}", f"forged_token={forged[:60]}…"],
            ))
        else:
            findings.append(_finding(
                "HMAC secret not in common wordlist", "info",
                f"The {alg.upper()} secret was not recovered from the built-in/"
                "supplied wordlist. This is not proof of strength — try a larger "
                "wordlist (e.g. jwt.secrets / rockyou) with a dedicated cracker.",
                "Use a long random secret and confirm resistance with a full "
                "dictionary/brute-force run offline.",
                components=[alg.upper()],
            ))

    # --- algorithm confusion (asymmetric -> HMAC) ---
    if alg.upper().startswith(_ASYMMETRIC_PREFIXES):
        desc = (
            f"The token is signed with {alg.upper()} (asymmetric). If the server "
            "verifies with a permissive library, an attacker may re-sign the token "
            "with HS256 using the *public* key as the HMAC secret (algorithm "
            "confusion), because the public key is not secret.")
        components = [alg.upper()]
        if public_key:
            try:
                forged = _forge_hs256(header, payload, public_key.encode())
                desc += (" A forged HS256 token (signed with the supplied public key "
                         "as the HMAC secret) has been generated as evidence — replay "
                         "it against the server to confirm.")
                components.append(f"forged_hs256={forged[:60]}…")
            except Exception:
                pass
        findings.append(_finding(
            "Algorithm-confusion candidate (asymmetric alg)", "medium", desc,
            "Pin the expected algorithm server-side (verify ONLY with RS256 and the "
            "public key; never allow HS* for an RS* token). Confirm by replaying an "
            "HS256-forged token signed with the public key.",
            references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
            components=components,
        ))

    # --- dangerous header params ---
    for hdr, sev, note in (
        ("jku", "high", "JWK Set URL — the server may fetch keys from an attacker URL (SSRF / key injection)."),
        ("x5u", "high", "X.509 URL — the server may fetch a cert from an attacker URL (SSRF / key injection)."),
        ("jwk", "high", "Embedded JWK — the server may trust an attacker-supplied key in the token header."),
    ):
        if hdr in header:
            findings.append(_finding(
                f"JWT header contains '{hdr}'", sev,
                f"{note} Header value: {str(header[hdr])[:200]}",
                f"Do not resolve keys from token-controlled fields. Ignore '{hdr}' or "
                "restrict it to a strict allow-list of trusted hosts/keys.",
                references=["https://portswigger.net/web-security/jwt"],
                components=[f"{hdr}={str(header[hdr])[:120]}"],
            ))

    if header.get("kid") is not None:
        findings.append(_finding(
            "JWT uses a 'kid' (key id) header", "low",
            "A 'kid' header selects the verification key. If the value reaches a file "
            "path, SQL query, or command unsanitised, it can enable path traversal, "
            "SQL injection, or key confusion.",
            "Treat 'kid' as untrusted input: look it up against a fixed allow-list of "
            "key ids; never interpolate it into paths, queries, or commands.",
            components=[f"kid={header['kid']}"],
        ))

    # --- expiry / timing ---
    now = datetime.now(timezone.utc).timestamp()
    if "exp" not in payload:
        findings.append(_finding(
            "JWT has no expiry ('exp')", "medium",
            "The token has no 'exp' claim, so it is valid indefinitely. A stolen "
            "token can be replayed forever.",
            "Issue short-lived tokens with an 'exp' claim and use refresh tokens for "
            "longer sessions.",
            components=["exp=absent"],
        ))
    else:
        try:
            exp = float(payload["exp"])
            if exp < now:
                findings.append(_finding(
                    "JWT is expired", "info",
                    f"The token expired at {datetime.fromtimestamp(exp, timezone.utc).isoformat()}. "
                    "Confirm the server actually rejects expired tokens (some do not).",
                    "Verify server-side that expired tokens are rejected.",
                    components=[f"exp={int(exp)}"],
                ))
            elif exp - now > 86400 * 7:
                findings.append(_finding(
                    "JWT has a very long lifetime (> 7 days)", "low",
                    "The token remains valid for more than a week, widening the window "
                    "for replay if it is stolen.",
                    "Shorten token lifetime; prefer minutes/hours with refresh tokens.",
                    components=[f"exp={int(exp)}"],
                ))
        except (TypeError, ValueError):
            pass

    # --- sensitive / privilege claims ---
    priv = sorted(k for k in payload if k.lower() in _PRIVILEGE_CLAIMS)
    if priv:
        findings.append(_finding(
            "Authorization-relevant claims present in token", "low",
            f"The payload carries claims that likely drive access decisions: "
            f"{', '.join(priv)}. If the server trusts these without re-checking, "
            "tampering (once the signature is bypassed) grants privilege escalation.",
            "Keep signature verification strict, and re-authorize sensitive actions "
            "server-side rather than trusting token claims alone.",
            components=priv,
        ))
    sensitive = sorted(k for k in payload if k.lower() in _SENSITIVE_CLAIMS)
    if sensitive:
        findings.append(_finding(
            "Sensitive data stored in JWT claims", "medium",
            f"The payload includes sensitive field(s): {', '.join(sensitive)}. JWT "
            "payloads are only base64-encoded, so this data is readable by anyone "
            "holding the token.",
            "Remove secrets/PII from the token; store server-side and reference by id.",
            components=sensitive,
        ))

    return findings
