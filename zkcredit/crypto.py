"""
Prime-order Pedersen Commitment Group and Fiat-Shamir Zero-Knowledge Primitives.

Implements:
- The prime-order subgroup of Curve25519 in Edwards form (order L = 2^252 + 2774...3493),
  with point arithmetic from libsodium (via PyNaCl). Points are 32-byte compressed encodings.
- Generator g = the standard Ed25519 base point; generator h derived by SHA-512
  try-and-increment hash-to-curve so log_g(h) is unknown (nothing up my sleeve).
- Homomorphic Pedersen commitment C(v, r) = v*g + r*h.
- Fiat-Shamir non-interactive Schnorr proof of opening (v, r), zero-value proof, and equality proof.

This is a reference implementation for study. The group operations come from libsodium,
but the protocols on top are hand-written and have not been independently reviewed.
Scalar arithmetic uses Python integers, which are not constant-time.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Dict

import nacl.bindings as sodium

# Order of the Ed25519 prime-order subgroup
ED25519_L = 2**252 + 27742317777372353535851937790883648493

# Encoding of the neutral element (x = 0, y = 1). libsodium rejects it as a public point,
# so it only ever appears as an intermediate value.
IDENTITY = bytes([1]) + bytes(31)


def is_prime_order_point(c: Any) -> bool:
    """
    True if c canonically encodes a non-identity point of the prime-order subgroup.

    libsodium's is_valid_point only rejects small-order and off-curve points in the version
    PyNaCl 1.5 ships, so a point with a torsion component would pass it. We also require
    L*c == identity, computed as (L-1)*c + c because libsodium refuses to output the identity.
    """
    if not (isinstance(c, bytes) and len(c) == 32 and sodium.crypto_core_ed25519_is_valid_point(c)):
        return False
    minus_c = sodium.crypto_scalarmult_ed25519_noclamp((ED25519_L - 1).to_bytes(32, "little"), c)
    return sodium.crypto_core_ed25519_add(minus_c, c) == IDENTITY


def hash_to_group(label: bytes) -> bytes:
    """
    Deterministically maps a domain-separated label to a point of the prime-order subgroup
    by SHA-512 try-and-increment: the first candidate encoding that is a prime-order point
    (about 1 in 16 candidates). Nobody knows its discrete log.
    """
    counter = 0
    while True:
        candidate = hashlib.sha512(
            b"zkcredit.hash_to_group.v2|" + label + b"|" + counter.to_bytes(4, "big")
        ).digest()[:32]
        if is_prime_order_point(candidate):
            return candidate
        counter += 1


def hash_to_scalar(*parts: Any, q: int) -> int:
    """
    Fiat-Shamir transcript hash mapping arbitrary domain-separated inputs to Z_q^* (in [1, q-1]).
    """
    h = hashlib.sha512(b"zkcredit.fiat_shamir.v2")
    for part in parts:
        if isinstance(part, bytes):
            b = b"b" + part
        elif isinstance(part, str):
            b = b"s" + part.encode("utf-8")
        elif isinstance(part, int):
            # Signed big-endian length-prefixed encoding
            sign = b"-" if part < 0 else b"+"
            mag = abs(part)
            nbytes = max(1, (mag.bit_length() + 7) // 8)
            b = b"i" + sign + mag.to_bytes(nbytes, "big")
        else:
            raise TypeError(f"Cannot hash transcript part of type {type(part).__name__}")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    val = int.from_bytes(h.digest(), "big") % (q - 1)
    return val + 1


@dataclass(frozen=True)
class PedersenGroup:
    """
    Prime-order Pedersen commitment group of order q with independent generators g, h
    (32-byte compressed Edwards points) and unknown log_g(h).
    """

    q: int
    g: bytes
    h: bytes
    name: str = "ed25519"

    def is_valid_element(self, c: Any) -> bool:
        """Checks c is a canonical encoding of a non-identity point in the prime-order subgroup."""
        return is_prime_order_point(c)

    def random_scalar(self) -> int:
        """Samples a cryptographically secure scalar in [1, q-1]."""
        return 1 + secrets.randbelow(self.q - 1)

    def mul(self, point: bytes, scalar: int) -> bytes:
        """Scalar multiplication k*P (P^k in multiplicative notation)."""
        k = scalar % self.q
        if k == 0 or point == IDENTITY:
            return IDENTITY
        return sodium.crypto_scalarmult_ed25519_noclamp(k.to_bytes(32, "little"), point)

    def commit(self, value: int, blinding: int | None = None) -> tuple[bytes, int]:
        """
        Computes Pedersen commitment C(v, r) = v*g + r*h.
        Supports positive, zero, and negative integer values via reduction mod q.
        Returns (commitment, blinding).
        """
        r = self.random_scalar() if blinding is None else (blinding % self.q)
        c = self.add_commitments(self.mul(self.g, value), self.mul(self.h, r))
        return c, r

    def add_commitments(self, c1: bytes, c2: bytes) -> bytes:
        """Homomorphic addition: C(v1, r1) + C(v2, r2) = C(v1 + v2, r1 + r2)."""
        return sodium.crypto_core_ed25519_add(c1, c2)

    def sub_commitments(self, c1: bytes, c2: bytes) -> bytes:
        """Homomorphic subtraction: C(v1, r1) - C(v2, r2) = C(v1 - v2, r1 - r2)."""
        return sodium.crypto_core_ed25519_sub(c1, c2)

    def shift_commitment(self, c: bytes, constant_shift: int) -> bytes:
        """Shifts committed value by a public integer constant: C(v, r) + k*g = C(v + k, r)."""
        return self.add_commitments(c, self.mul(self.g, constant_shift))

    def verify_opening(self, commitment: bytes, value: int, blinding: int) -> bool:
        """Verifies that commitment == v*g + r*h."""
        if not self.is_valid_element(commitment):
            return False
        expected, _ = self.commit(value, blinding)
        return commitment == expected


DEFAULT_GROUP = PedersenGroup(
    q=ED25519_L,
    g=sodium.crypto_scalarmult_ed25519_base_noclamp((1).to_bytes(32, "little")),
    h=hash_to_group(b"ZKCREDIT-GENERATOR-H-V2-NOTHING-UP-MY-SLEEVE"),
)


@dataclass(frozen=True)
class OpeningProof:
    """Fiat-Shamir Schnorr proof of knowledge of (v, r) such that C = v*g + r*h."""

    commitment: bytes
    announcement: bytes
    challenge: int
    response_v: int
    response_r: int
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": self.commitment.hex(),
            "announcement": self.announcement.hex(),
            "challenge": hex(self.challenge),
            "response_v": hex(self.response_v),
            "response_r": hex(self.response_r),
            "context": self.context,
        }


@dataclass(frozen=True)
class ZeroCommitmentProof:
    """
    Fiat-Shamir Schnorr proof that C = 0*g + r*h commits to 0
    (i.e. proof of knowledge of r = log_h(C)).
    """

    commitment: bytes
    announcement: bytes
    challenge: int
    response_r: int
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": self.commitment.hex(),
            "announcement": self.announcement.hex(),
            "challenge": hex(self.challenge),
            "response_r": hex(self.response_r),
            "context": self.context,
        }


def prove_opening(
    value: int,
    blinding: int,
    commitment: bytes | None = None,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> OpeningProof:
    """Generates a non-interactive zero-knowledge Schnorr proof of knowledge of opening (v, r)."""
    c_val, r_mod = group.commit(value, blinding)
    if commitment is not None and commitment != c_val:
        raise ValueError("Provided commitment does not match (value, blinding).")

    kv = group.random_scalar()
    kr = group.random_scalar()
    announcement, _ = group.commit(kv, kr)
    challenge = hash_to_scalar(
        "zkcredit.opening.v2",
        group.g,
        group.h,
        c_val,
        announcement,
        context,
        q=group.q,
    )
    sv = (kv + challenge * (value % group.q)) % group.q
    sr = (kr + challenge * r_mod) % group.q
    return OpeningProof(
        commitment=c_val,
        announcement=announcement,
        challenge=challenge,
        response_v=sv,
        response_r=sr,
        context=context,
    )


def verify_opening_proof(
    proof: OpeningProof,
    expected_commitment: bytes | None = None,
    context: str | None = None,
    group: PedersenGroup = DEFAULT_GROUP,
) -> bool:
    """Verifies a Fiat-Shamir Schnorr proof of knowledge of opening (v, r)."""
    if expected_commitment is not None and proof.commitment != expected_commitment:
        return False
    if context is not None and proof.context != context:
        return False
    if not group.is_valid_element(proof.commitment) or not group.is_valid_element(proof.announcement):
        return False
    if not (0 <= proof.response_v < group.q and 0 <= proof.response_r < group.q):
        return False

    expected_challenge = hash_to_scalar(
        "zkcredit.opening.v2",
        group.g,
        group.h,
        proof.commitment,
        proof.announcement,
        proof.context,
        q=group.q,
    )
    if proof.challenge != expected_challenge:
        return False

    lhs, _ = group.commit(proof.response_v, proof.response_r)
    rhs = group.add_commitments(proof.announcement, group.mul(proof.commitment, proof.challenge))
    return lhs == rhs


def prove_zero_commitment(
    blinding: int,
    commitment: bytes | None = None,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> ZeroCommitmentProof:
    """Proves in zero knowledge that C = r*h opens to v = 0."""
    c_val, r_mod = group.commit(0, blinding)
    if commitment is not None and commitment != c_val:
        raise ValueError("Commitment does not open to zero with the given blinding factor.")

    kr = group.random_scalar()
    announcement = group.mul(group.h, kr)
    challenge = hash_to_scalar(
        "zkcredit.zero.v2",
        group.g,
        group.h,
        c_val,
        announcement,
        context,
        q=group.q,
    )
    sr = (kr + challenge * r_mod) % group.q
    return ZeroCommitmentProof(
        commitment=c_val,
        announcement=announcement,
        challenge=challenge,
        response_r=sr,
        context=context,
    )


def verify_zero_commitment(
    proof: ZeroCommitmentProof,
    expected_commitment: bytes | None = None,
    context: str | None = None,
    group: PedersenGroup = DEFAULT_GROUP,
) -> bool:
    """Verifies a Fiat-Shamir proof that a Pedersen commitment opens to v = 0."""
    if expected_commitment is not None and proof.commitment != expected_commitment:
        return False
    if context is not None and proof.context != context:
        return False
    if not group.is_valid_element(proof.commitment) or not group.is_valid_element(proof.announcement):
        return False
    if not (0 <= proof.response_r < group.q):
        return False

    expected_challenge = hash_to_scalar(
        "zkcredit.zero.v2",
        group.g,
        group.h,
        proof.commitment,
        proof.announcement,
        proof.context,
        q=group.q,
    )
    if proof.challenge != expected_challenge:
        return False

    lhs = group.mul(group.h, proof.response_r)
    rhs = group.add_commitments(proof.announcement, group.mul(proof.commitment, proof.challenge))
    return lhs == rhs


def prove_equality(
    value: int,
    c1: bytes,
    r1: int,
    c2: bytes,
    r2: int,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> ZeroCommitmentProof:
    """
    Proves that two Pedersen commitments C1 = C(v, r1) and C2 = C(v, r2) commit to the
    exact same value v without revealing v, by proving C1 - C2 commits to 0.
    """
    if not (group.verify_opening(c1, value, r1) and group.verify_opening(c2, value, r2)):
        raise ValueError("Commitments C1 and C2 do not open to the same value.")
    c_diff = group.sub_commitments(c1, c2)
    r_diff = (r1 - r2) % group.q
    return prove_zero_commitment(r_diff, commitment=c_diff, context=context, group=group)


def verify_equality(
    c1: bytes,
    c2: bytes,
    proof: ZeroCommitmentProof,
    context: str | None = None,
    group: PedersenGroup = DEFAULT_GROUP,
) -> bool:
    """Verifies that C1 and C2 hide the same value v via the quotient zero-commitment proof."""
    if not (group.is_valid_element(c1) and group.is_valid_element(c2)):
        return False
    c_diff = group.sub_commitments(c1, c2)
    return verify_zero_commitment(proof, expected_commitment=c_diff, context=context, group=group)
