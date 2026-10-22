"""
Prime-order Schnorr / Pedersen Commitment Group and Fiat-Shamir Zero-Knowledge Primitives.

Implements:
- 256-bit Safe Prime group p = 2q + 1 where q is a 255-bit Sophie Germain prime.
- Prime-order subgroup G_q of quadratic residues modulo p with generators g, h.
- Nothing-up-my-sleeve generator h derived via SHA-256 hash-to-group so log_g(h) is unknown.
- Homomorphic Pedersen commitment C(v, r) = g^v * h^r mod p.
- Fiat-Shamir non-interactive Schnorr proof of opening (v, r), zero-value proof, and equality proof.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import asdict, dataclass
from typing import Any, Dict, Sequence


# Deterministic Miller-Rabin bases sufficient and strong for 256-bit primality testing
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

# Pre-sieve primes for fast safe-prime verification/derivation
_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
    163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
    241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
    337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
    521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
    617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
    719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821,
    823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919,
    929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
)


def is_prime(n: int) -> bool:
    """Probabilistic Miller-Rabin primality test with 12 bases (error < 4^-12)."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in _MR_BASES:
        if a >= n:
            break
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def derive_safe_prime_256(seed: bytes = b"ZKCREDIT-NOTHING-UP-MY-SLEEVE-SAFE-PRIME-256") -> tuple[int, int]:
    """
    Deterministically derives a 256-bit safe prime p = 2q + 1 from a nothing-up-my-sleeve
    SHA-256 seed using joint small-prime sieving on (q, 2q + 1).
    """
    raw = int.from_bytes(hashlib.sha256(seed).digest(), "big")
    # Ensure p = 2q + 1 is 256 bits, so q is 255 bits (bit 254 set)
    q_base = (raw | (1 << 254)) & ((1 << 255) - 1)
    # Require q == 5 (mod 6) so 2q + 1 == 11 == 5 (mod 6) and q == 3 (mod 4) so 2q + 1 == 7 (mod 8)
    # Concretely, q == 11 (mod 12) guarantees 2 | (q+1), 3 | (q+1), and p == 23 (mod 24).
    rem = q_base % 12
    q_start = q_base + ((11 - rem) % 12)

    # Precompute residues mod each small prime > 3
    sieve_primes = _SMALL_PRIMES[1:]  # skip 3 since q == 2 mod 3 already
    step = 12
    window = 30000
    offset = 0

    while True:
        # Sieve window of candidates q_i = q_start + (offset + i) * 12
        alive = bytearray([1]) * window
        base_q = q_start + offset * step
        for sp in sieve_primes:
            # Eliminate q_i % sp == 0 and (2*q_i + 1) % sp == 0 => q_i % sp == (sp - 1) // 2
            step_mod = step % sp
            inv_step = pow(step_mod, -1, sp)
            r0 = base_q % sp
            # Solve r0 + i * step_mod == 0 (mod sp)
            i1 = ((-r0) * inv_step) % sp
            # Solve r0 + i * step_mod == (sp - 1) // 2 (mod sp)
            target2 = (sp - 1) // 2
            i2 = ((target2 - r0) * inv_step) % sp
            for idx in range(i1, window, sp):
                alive[idx] = 0
            for idx in range(i2, window, sp):
                alive[idx] = 0

        for i, ok in enumerate(alive):
            if not ok:
                continue
            q = base_q + i * step
            # Fast joint Fermat base-2 filter before full Miller-Rabin
            if pow(2, q - 1, q) != 1:
                continue
            p = 2 * q + 1
            if pow(2, p - 1, p) != 1:
                continue
            if is_prime(q) and is_prime(p):
                return p, q
        offset += window


def hash_to_group(label: bytes, p: int, q: int, forbidden: Sequence[int] = ()) -> int:
    """
    Deterministically maps a domain-separated label to a generator of the prime-order
    subgroup G_q of quadratic residues modulo safe prime p = 2q + 1, via SHA-256
    hash-and-square (nothing-up-my-sleeve, so discrete log is unknown).
    """
    forbidden_set = set(forbidden) | {0, 1, p - 1}
    counter = 0
    while True:
        digest = hashlib.sha256(
            b"zkcredit.hash_to_group.v1|"
            + label
            + b"|"
            + counter.to_bytes(4, "big")
            + p.to_bytes(32, "big")
        ).digest()
        candidate_root = 2 + (int.from_bytes(digest, "big") % (p - 3))
        elem = pow(candidate_root, 2, p)
        if elem not in forbidden_set and pow(elem, q, p) == 1:
            return elem
        counter += 1


def hash_to_scalar(*parts: Any, q: int) -> int:
    """
    Fiat-Shamir transcript hash mapping arbitrary domain-separated inputs to Z_q^* (in [1, q-1]).
    """
    h = hashlib.sha256(b"zkcredit.fiat_shamir.v1")
    for part in parts:
        if isinstance(part, bytes):
            b = part
        elif isinstance(part, str):
            b = part.encode("utf-8")
        elif isinstance(part, int):
            # Signed big-endian length-prefixed encoding
            sign = b"-" if part < 0 else b"+"
            mag = abs(part)
            nbytes = max(1, (mag.bit_length() + 7) // 8)
            b = sign + mag.to_bytes(nbytes, "big")
        elif isinstance(part, (list, tuple)):
            b = b"[" + b",".join(str(x).encode("utf-8") for x in part) + b"]"
        else:
            b = str(part).encode("utf-8")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    val = int.from_bytes(h.digest(), "big") % (q - 1)
    return val + 1


@dataclass(frozen=True)
class PedersenGroup:
    """
    Prime-order Pedersen commitment group G_q subset Z_p^* of order q, where p = 2q + 1
    is a 256-bit safe prime and g, h are independent generators of G_q with unknown log_g(h).
    """

    p: int
    q: int
    g: int
    h: int

    def is_valid_element(self, c: int) -> bool:
        """Checks whether c belongs to the prime-order subgroup G_q subset Z_p^*."""
        return 1 <= c < self.p and pow(c, self.q, self.p) == 1

    def random_scalar(self) -> int:
        """Samples a cryptographically secure blinding factor r in [1, q-1]."""
        return 1 + secrets.randbelow(self.q - 1)

    def commit(self, value: int, blinding: int | None = None) -> tuple[int, int]:
        """
        Computes Pedersen commitment C(v, r) = g^v * h^r mod p.
        Supports positive, zero, and negative integer values via reduction mod q.
        Returns (commitment, blinding).
        """
        r = self.random_scalar() if blinding is None else (blinding % self.q)
        v_mod = value % self.q
        c = (pow(self.g, v_mod, self.p) * pow(self.h, r, self.p)) % self.p
        return c, r

    def add_commitments(self, c1: int, c2: int) -> int:
        """Homomorphic addition: C(v1, r1) * C(v2, r2) mod p = C(v1 + v2, r1 + r2)."""
        return (c1 * c2) % self.p

    def sub_commitments(self, c1: int, c2: int) -> int:
        """Homomorphic subtraction: C(v1, r1) * C(v2, r2)^(-1) mod p = C(v1 - v2, r1 - r2)."""
        return (c1 * pow(c2, -1, self.p)) % self.p

    def scale_commitment(self, c: int, scalar: int) -> int:
        """Homomorphic scalar multiplication: C(v, r)^k mod p = C(k * v, k * r)."""
        return pow(c, scalar % self.q, self.p)

    def shift_commitment(self, c: int, constant_shift: int) -> int:
        """
        Shifts committed value by a public integer constant:
        C(v, r) * g^(constant_shift) mod p = C(v + constant_shift, r).
        """
        return (c * pow(self.g, constant_shift % self.q, self.p)) % self.p

    def verify_opening(self, commitment: int, value: int, blinding: int) -> bool:
        """Verifies that commitment == g^value * h^blinding mod p."""
        if not self.is_valid_element(commitment):
            return False
        expected, _ = self.commit(value, blinding)
        return commitment == expected


# Initialize and cache the default 256-bit safe-prime Pedersen group
_DEFAULT_P, _DEFAULT_Q = derive_safe_prime_256()
_DEFAULT_G = hash_to_group(b"ZKCREDIT-GENERATOR-G-V1", _DEFAULT_P, _DEFAULT_Q)
_DEFAULT_H = hash_to_group(
    b"ZKCREDIT-GENERATOR-H-V1-NOTHING-UP-MY-SLEEVE",
    _DEFAULT_P,
    _DEFAULT_Q,
    forbidden=(_DEFAULT_G,),
)

DEFAULT_GROUP = PedersenGroup(
    p=_DEFAULT_P,
    q=_DEFAULT_Q,
    g=_DEFAULT_G,
    h=_DEFAULT_H,
)


@dataclass(frozen=True)
class OpeningProof:
    """Fiat-Shamir Schnorr proof of knowledge of (v, r) such that C = g^v * h^r mod p."""

    commitment: int
    announcement: int
    challenge: int
    response_v: int
    response_r: int
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": hex(self.commitment),
            "announcement": hex(self.announcement),
            "challenge": hex(self.challenge),
            "response_v": hex(self.response_v),
            "response_r": hex(self.response_r),
            "context": self.context,
        }


@dataclass(frozen=True)
class ZeroCommitmentProof:
    """
    Fiat-Shamir Schnorr proof that C = g^0 * h^r mod p commits to 0
    (i.e. proof of knowledge of r = log_h(C)).
    """

    commitment: int
    announcement: int
    challenge: int
    response_r: int
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": hex(self.commitment),
            "announcement": hex(self.announcement),
            "challenge": hex(self.challenge),
            "response_r": hex(self.response_r),
            "context": self.context,
        }


def prove_opening(
    value: int,
    blinding: int,
    commitment: int | None = None,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> OpeningProof:
    """Generates a non-interactive zero-knowledge Schnorr proof of knowledge of opening (v, r)."""
    c_val, r_mod = group.commit(value, blinding)
    if commitment is not None and commitment != c_val:
        raise ValueError("Provided commitment does not match (value, blinding).")

    kv = group.random_scalar()
    kr = group.random_scalar()
    announcement = (pow(group.g, kv, group.p) * pow(group.h, kr, group.p)) % group.p
    challenge = hash_to_scalar(
        "zkcredit.opening.v1",
        group.p,
        group.q,
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
    expected_commitment: int | None = None,
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
        "zkcredit.opening.v1",
        group.p,
        group.q,
        group.g,
        group.h,
        proof.commitment,
        proof.announcement,
        proof.context,
        q=group.q,
    )
    if proof.challenge != expected_challenge:
        return False

    lhs = (pow(group.g, proof.response_v, group.p) * pow(group.h, proof.response_r, group.p)) % group.p
    rhs = (proof.announcement * pow(proof.commitment, proof.challenge, group.p)) % group.p
    return lhs == rhs


def prove_zero_commitment(
    blinding: int,
    commitment: int | None = None,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> ZeroCommitmentProof:
    """Proves in zero knowledge that C = h^r mod p opens to v = 0."""
    c_val, r_mod = group.commit(0, blinding)
    if commitment is not None and commitment != c_val:
        raise ValueError("Commitment does not open to zero with the given blinding factor.")

    kr = group.random_scalar()
    announcement = pow(group.h, kr, group.p)
    challenge = hash_to_scalar(
        "zkcredit.zero.v1",
        group.p,
        group.q,
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
    expected_commitment: int | None = None,
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
        "zkcredit.zero.v1",
        group.p,
        group.q,
        group.g,
        group.h,
        proof.commitment,
        proof.announcement,
        proof.context,
        q=group.q,
    )
    if proof.challenge != expected_challenge:
        return False

    lhs = pow(group.h, proof.response_r, group.p)
    rhs = (proof.announcement * pow(proof.commitment, proof.challenge, group.p)) % group.p
    return lhs == rhs


def prove_equality(
    value: int,
    c1: int,
    r1: int,
    c2: int,
    r2: int,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> ZeroCommitmentProof:
    """
    Proves that two Pedersen commitments C1 = C(v, r1) and C2 = C(v, r2) commit to the
    exact same value v without revealing v, by proving C1 * C2^(-1) commits to 0.
    """
    if not (group.verify_opening(c1, value, r1) and group.verify_opening(c2, value, r2)):
        raise ValueError("Commitments C1 and C2 do not open to the same value.")
    c_diff = group.sub_commitments(c1, c2)
    r_diff = (r1 - r2) % group.q
    return prove_zero_commitment(r_diff, commitment=c_diff, context=context, group=group)


def verify_equality(
    c1: int,
    c2: int,
    proof: ZeroCommitmentProof,
    context: str | None = None,
    group: PedersenGroup = DEFAULT_GROUP,
) -> bool:
    """Verifies that C1 and C2 hide the same value v via the quotient zero-commitment proof."""
    if not (group.is_valid_element(c1) and group.is_valid_element(c2)):
        return False
    c_diff = group.sub_commitments(c1, c2)
    return verify_zero_commitment(proof, expected_commitment=c_diff, context=context, group=group)
