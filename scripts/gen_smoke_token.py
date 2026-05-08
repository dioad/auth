#!/usr/bin/env python3
"""gen_smoke_token.py — generates an HS256 JWT for local smoke testing.

The token is signed with a secret and carries one or more roles.
The issuer defaults to "local-smoke" but can be overridden with --issuer.

Usage (positional roles):
    ./scripts/gen_smoke_token.py
    ./scripts/gen_smoke_token.py --role connect-admin --role connect-user
    TOKEN=$(./scripts/gen_smoke_token.py --role connect-admin)
    curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8120/tunnel

    # Write an oauth2.Token YAML file (for identity.token-file configs):
    ./scripts/gen_smoke_token.py --role registry.publisher --write-token-file /tmp/smoke-server-token.yaml

Environment variable fallbacks (all overridden by CLI flags):
    SMOKE_JWT_SECRET    — signing secret (default: local-smoke-test-secret)
    SMOKE_JWT_ROLES     — comma-separated roles (default: connect-admin)
    SMOKE_JWT_SUBJECT   — token subject (default: smoke-test-user)
    SMOKE_JWT_AUDIENCE  — token audience (default: local-smoke)
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def build_token(secret: str, roles: list[str], subject: str, issuer: str, audience: str, ttl: int) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + ttl,
        "roles": roles,
    }

    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def write_token_file(path: str, token: str, ttl: int) -> None:
    """Write an oauth2.Token YAML file for use with identity.token-file configs.

    The file is written with mode 0600 (owner read/write only) to prevent
    other users on the system from reading the bearer token credential.

    The fields use the lowercase names produced by Go's yaml.v3 marshaller
    when no YAML struct tags are present (AccessToken → accesstoken, etc.).
    """
    expiry = datetime.datetime.fromtimestamp(time.time() + ttl, tz=datetime.timezone.utc)
    expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
    content = (
        f"accesstoken: {token}\n"
        f"tokentype: Bearer\n"
        f"expiry: {expiry_str}\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(path, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an HS256 JWT for local smoke testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--secret",
        default=os.environ.get("SMOKE_JWT_SECRET", "local-smoke-test-secret"),
        help="HMAC signing secret (env: SMOKE_JWT_SECRET)",
    )
    parser.add_argument(
        "--role",
        dest="roles",
        action="append",
        metavar="ROLE",
        help="Role to include in the token; may be specified multiple times. "
             "Falls back to SMOKE_JWT_ROLES env var (comma-separated) when not provided.",
    )
    parser.add_argument(
        "--subject",
        default=os.environ.get("SMOKE_JWT_SUBJECT", "smoke-test-user"),
        help="Token subject (env: SMOKE_JWT_SUBJECT)",
    )
    parser.add_argument(
        "--issuer",
        default="local-smoke",
        help="Token issuer (default: local-smoke)",
    )
    parser.add_argument(
        "--audience",
        default=os.environ.get("SMOKE_JWT_AUDIENCE", "local-smoke"),
        help="Token audience (env: SMOKE_JWT_AUDIENCE, default: local-smoke)",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="Token lifetime in seconds (default: 3600)",
    )
    parser.add_argument(
        "--write-token-file",
        metavar="PATH",
        help="Write an oauth2.Token YAML file to PATH (for use with identity.token-file configs). "
             "The JWT is still printed to stdout.",
    )

    args = parser.parse_args()

    # Resolve roles: CLI flags take precedence, then env var, then default.
    if args.roles:
        roles = args.roles
    else:
        env_roles = os.environ.get("SMOKE_JWT_ROLES", "connect-admin")
        roles = [r.strip() for r in env_roles.split(",") if r.strip()]

    if not args.secret:
        parser.error("--secret / SMOKE_JWT_SECRET must not be empty")

    token = build_token(
        secret=args.secret,
        roles=roles,
        subject=args.subject,
        issuer=args.issuer,
        audience=args.audience,
        ttl=args.ttl,
    )
    print(token)

    if args.write_token_file:
        write_token_file(args.write_token_file, token, args.ttl)


if __name__ == "__main__":
    main()
