"""Issue and check session tokens signed with RS256."""

import jwt


def issue(claims: dict, private_pem: str) -> str:
    return jwt.encode(claims, private_pem, algorithm="RS256")


def check(token: str, public_pem: str) -> dict:
    return jwt.decode(token, public_pem, algorithms=["RS256"])
