"""
Bit-Decomposition CDS OR-Sigma Range Proofs over Pedersen Commitments.

Proves in zero knowledge that a committed value v satisfies:
  v - lower_bound in [0, 2^bit_length)
without revealing v or its blinding factor r.

Construction:
1. Shift commitment by lower_bound: C' = C(v, r) - lower_bound*g = C(v - lower_bound, r).
2. Decompose v' = v - lower_bound into k bits: v' = sum_{j=0}^{k-1} b_j * 2^j with b_j in {0, 1}.
3. Sample random bit blindings r_0, ..., r_{k-2} in Z_q and set
     r_{k-1} = (r - sum_{j=0}^{k-2} 2^j * r_j) * (2^{k-1})^(-1) mod q
   so that sum_{j=0}^{k-1} 2^j * r_j == r (mod q) and
     sum_{j=0}^{k-1} 2^j * C_j == C'.
4. For each bit commitment C_j = b_j*g + r_j*h, prove b_j in {0, 1} using a
   1-of-2 Cramer-Damgard-Schoenmakers (CDS) OR-Sigma proof via Fiat-Shamir.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .crypto import DEFAULT_GROUP, IDENTITY, PedersenGroup, hash_to_scalar


@dataclass(frozen=True)
class BitOrProof:
    """
    1-of-2 CDS OR-Sigma proof that bit_commitment C_j = b_j*g + r_j*h
    opens to b_j = 0 OR b_j = 1.

    Verification equations:
      Y_0 = C_j,         s_0*h == T_0 + e_0*Y_0
      Y_1 = C_j - g,     s_1*h == T_1 + e_1*Y_1
      (e_0 + e_1) mod q == H("zkcredit.bit_or.v2", g, h, parent_C, bit_index, C_j, T_0, T_1, context)
    """

    bit_index: int
    bit_commitment: bytes
    t0: bytes
    t1: bytes
    e0: int
    e1: int
    s0: int
    s1: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bit_index": self.bit_index,
            "bit_commitment": self.bit_commitment.hex(),
            "t0": self.t0.hex(),
            "t1": self.t1.hex(),
            "e0": hex(self.e0),
            "e1": hex(self.e1),
            "s0": hex(self.s0),
            "s1": hex(self.s1),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BitOrProof":
        return cls(
            bit_index=int(data["bit_index"]),
            bit_commitment=bytes.fromhex(str(data["bit_commitment"])),
            t0=bytes.fromhex(str(data["t0"])),
            t1=bytes.fromhex(str(data["t1"])),
            e0=int(str(data["e0"]), 0),
            e1=int(str(data["e1"]), 0),
            s0=int(str(data["s0"]), 0),
            s1=int(str(data["s1"]), 0),
        )


@dataclass(frozen=True)
class RangeProof:
    """
    Zero-knowledge range proof attesting that C = v*g + r*h satisfies
    v >= lower_bound and v - lower_bound < 2^bit_length.
    """

    commitment: bytes
    shifted_commitment: bytes
    lower_bound: int
    bit_length: int
    bit_proofs: List[BitOrProof]
    context: str = ""

    def byte_size(self) -> int:
        """Compact serialized size in bytes (each bit proof stores C_j, e0, e1, s0, s1 as 32-byte scalars)."""
        # Header: commitment (32B) + lower_bound (8B) + bit_length (2B)
        # Per bit: C_j (32B) + e0 (32B) + e1 (32B) + s0 (32B) + s1 (32B) = 160B
        return 42 + self.bit_length * 160

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": self.commitment.hex(),
            "shifted_commitment": self.shifted_commitment.hex(),
            "lower_bound": self.lower_bound,
            "bit_length": self.bit_length,
            "bit_proofs": [bp.to_dict() for bp in self.bit_proofs],
            "context": self.context,
            "byte_size": self.byte_size(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RangeProof":
        return cls(
            commitment=bytes.fromhex(str(data["commitment"])),
            shifted_commitment=bytes.fromhex(str(data["shifted_commitment"])),
            lower_bound=int(data["lower_bound"]),
            bit_length=int(data["bit_length"]),
            bit_proofs=[BitOrProof.from_dict(bp) for bp in data["bit_proofs"]],
            context=str(data.get("context", "")),
        )


def _prove_bit_or(
    bit: int,
    bit_blinding: int,
    bit_commitment: bytes,
    parent_shifted_commitment: bytes,
    bit_index: int,
    context: str,
    group: PedersenGroup,
) -> BitOrProof:
    """
    Constructs a 1-of-2 CDS OR-Sigma proof that bit_commitment commits to 0 OR 1.
    """
    if bit not in (0, 1):
        raise ValueError(f"Bit must be 0 or 1, got {bit}")

    y0 = bit_commitment
    y1 = group.sub_commitments(bit_commitment, group.g)

    # Nonce k for the true branch, random challenge & response for the simulated branch
    k = group.random_scalar()
    sim_e = group.random_scalar()
    sim_s = group.random_scalar()

    if bit == 0:
        # True branch is 0 (y0 = h^r_j), simulated branch is 1
        t0 = group.mul(group.h, k)
        t1 = group.sub_commitments(group.mul(group.h, sim_s), group.mul(y1, sim_e))
        e_total = hash_to_scalar(
            "zkcredit.bit_or.v2",
            group.g,
            group.h,
            parent_shifted_commitment,
            bit_index,
            bit_commitment,
            t0,
            t1,
            context,
            q=group.q,
        )
        e0 = (e_total - sim_e) % group.q
        e1 = sim_e
        s0 = (k + e0 * (bit_blinding % group.q)) % group.q
        s1 = sim_s
    else:
        # True branch is 1 (y1 = h^r_j), simulated branch is 0
        t1 = group.mul(group.h, k)
        t0 = group.sub_commitments(group.mul(group.h, sim_s), group.mul(y0, sim_e))
        e_total = hash_to_scalar(
            "zkcredit.bit_or.v2",
            group.g,
            group.h,
            parent_shifted_commitment,
            bit_index,
            bit_commitment,
            t0,
            t1,
            context,
            q=group.q,
        )
        e1 = (e_total - sim_e) % group.q
        e0 = sim_e
        s1 = (k + e1 * (bit_blinding % group.q)) % group.q
        s0 = sim_s

    return BitOrProof(
        bit_index=bit_index,
        bit_commitment=bit_commitment,
        t0=t0,
        t1=t1,
        e0=e0,
        e1=e1,
        s0=s0,
        s1=s1,
    )


def _verify_bit_or(
    bp: BitOrProof,
    parent_shifted_commitment: bytes,
    expected_bit_index: int,
    context: str,
    group: PedersenGroup,
) -> bool:
    """Verifies a single 1-of-2 CDS OR-Sigma bit proof."""
    if bp.bit_index != expected_bit_index:
        return False
    if not (
        group.is_valid_element(bp.bit_commitment)
        and group.is_valid_element(bp.t0)
        and group.is_valid_element(bp.t1)
    ):
        return False
    if not (
        0 <= bp.e0 < group.q
        and 0 <= bp.e1 < group.q
        and 0 <= bp.s0 < group.q
        and 0 <= bp.s1 < group.q
    ):
        return False

    y0 = bp.bit_commitment
    y1 = group.sub_commitments(bp.bit_commitment, group.g)

    # Check branch 0: s0*h == t0 + e0*y0
    lhs0 = group.mul(group.h, bp.s0)
    rhs0 = group.add_commitments(bp.t0, group.mul(y0, bp.e0))
    if lhs0 != rhs0:
        return False

    # Check branch 1: s1*h == t1 + e1*y1
    lhs1 = group.mul(group.h, bp.s1)
    rhs1 = group.add_commitments(bp.t1, group.mul(y1, bp.e1))
    if lhs1 != rhs1:
        return False

    # Check Fiat-Shamir challenge split: (e0 + e1) mod q == H(...)
    e_expected = hash_to_scalar(
        "zkcredit.bit_or.v2",
        group.g,
        group.h,
        parent_shifted_commitment,
        bp.bit_index,
        bp.bit_commitment,
        bp.t0,
        bp.t1,
        context,
        q=group.q,
    )
    return (bp.e0 + bp.e1) % group.q == e_expected


def prove_range(
    value: int,
    blinding: int,
    commitment: bytes | None = None,
    lower_bound: int = 0,
    bit_length: int = 24,
    context: str = "",
    group: PedersenGroup = DEFAULT_GROUP,
) -> RangeProof:
    """
    Proves in zero knowledge that `value >= lower_bound` and `value - lower_bound < 2^bit_length`.
    """
    if bit_length < 2 or bit_length > 64:
        raise ValueError("bit_length must be between 2 and 64.")

    c_actual, r_mod = group.commit(value, blinding)
    if commitment is not None and commitment != c_actual:
        raise ValueError("Provided commitment does not match (value, blinding).")

    shifted_val = value - lower_bound
    if shifted_val < 0 or shifted_val >= (1 << bit_length):
        raise ValueError(
            f"Value {value} is out of range [{lower_bound}, {lower_bound + (1 << bit_length)})."
        )

    c_shifted = group.shift_commitment(c_actual, -lower_bound)

    # Extract bits b_0, ..., b_{k-1}
    bits = [(shifted_val >> j) & 1 for j in range(bit_length)]

    # Sample k-1 random blindings and solve for r_{k-1} so sum_{j=0}^{k-1} 2^j * r_j == r (mod q)
    bit_blindings: List[int] = []
    running_sum = 0
    for j in range(bit_length - 1):
        rj = group.random_scalar()
        bit_blindings.append(rj)
        running_sum = (running_sum + (1 << j) * rj) % group.q

    inv_last_weight = pow(1 << (bit_length - 1), -1, group.q)
    r_last = ((r_mod - running_sum) * inv_last_weight) % group.q
    bit_blindings.append(r_last)

    bit_proofs: List[BitOrProof] = []
    for j in range(bit_length):
        cj, _ = group.commit(bits[j], bit_blindings[j])
        bp = _prove_bit_or(
            bit=bits[j],
            bit_blinding=bit_blindings[j],
            bit_commitment=cj,
            parent_shifted_commitment=c_shifted,
            bit_index=j,
            context=context,
            group=group,
        )
        bit_proofs.append(bp)

    return RangeProof(
        commitment=c_actual,
        shifted_commitment=c_shifted,
        lower_bound=lower_bound,
        bit_length=bit_length,
        bit_proofs=bit_proofs,
        context=context,
    )


def verify_range(
    proof: RangeProof,
    expected_commitment: bytes | None = None,
    expected_lower_bound: int | None = None,
    expected_bit_length: int | None = None,
    context: str | None = None,
    group: PedersenGroup = DEFAULT_GROUP,
) -> bool:
    """
    Verifies a zero-knowledge RangeProof using only public commitments and thresholds.
    """
    if expected_commitment is not None and proof.commitment != expected_commitment:
        return False
    if expected_lower_bound is not None and proof.lower_bound != expected_lower_bound:
        return False
    if expected_bit_length is not None and proof.bit_length != expected_bit_length:
        return False
    if context is not None and proof.context != context:
        return False
    if len(proof.bit_proofs) != proof.bit_length or proof.bit_length < 2:
        return False
    if not (
        group.is_valid_element(proof.commitment)
        and group.is_valid_element(proof.shifted_commitment)
    ):
        return False

    # 1. Verify that shifted_commitment == commitment - lower_bound*g
    expected_shifted = group.shift_commitment(proof.commitment, -proof.lower_bound)
    if proof.shifted_commitment != expected_shifted:
        return False

    # 2. Verify each 1-of-2 CDS OR-Sigma bit proof and accumulate homomorphic product
    reconstructed = IDENTITY
    for j, bp in enumerate(proof.bit_proofs):
        if not _verify_bit_or(bp, proof.shifted_commitment, j, proof.context, group):
            return False
        reconstructed = group.add_commitments(reconstructed, group.mul(bp.bit_commitment, 1 << j))

    # 3. Verify homomorphic bit-reconstruction: sum_{j=0}^{k-1} 2^j * C_j == shifted_commitment
    return reconstructed == proof.shifted_commitment


def forge_range_proof_attempt(
    actual_value: int,
    blinding: int,
    lower_bound: int = 0,
    bit_length: int = 24,
    context: str = "",
    strategy: str = "modular_wrap",
    group: PedersenGroup = DEFAULT_GROUP,
) -> RangeProof:
    """
    Simulates an adversarial prover attempting to forge a RangeProof for an out-of-range
    value (e.g. actual_value < lower_bound). Used for soundness benchmarking.

    Strategies:
    - "modular_wrap": Decomposes (actual_value - lower_bound) mod 2^bit_length into valid
      {0, 1} bit commitments with matching blinding sum, which fails the homomorphic
      product check against `commitment`.
    - "fake_bit_opening": Forces the last bit commitment C_{k-1} to absorb the negative
      difference so the homomorphic product holds, and attempts to forge the CDS OR proof.
    """
    c_actual, r_mod = group.commit(actual_value, blinding)
    c_shifted = group.shift_commitment(c_actual, -lower_bound)
    fake_nonneg = (actual_value - lower_bound) % (1 << bit_length)
    bits = [(fake_nonneg >> j) & 1 for j in range(bit_length)]

    bit_blindings: List[int] = []
    running_sum = 0
    for j in range(bit_length - 1):
        rj = group.random_scalar()
        bit_blindings.append(rj)
        running_sum = (running_sum + (1 << j) * rj) % group.q

    inv_last_weight = pow(1 << (bit_length - 1), -1, group.q)
    r_last = ((r_mod - running_sum) * inv_last_weight) % group.q
    bit_blindings.append(r_last)

    bit_proofs: List[BitOrProof] = []
    partial_product = IDENTITY
    for j in range(bit_length):
        if strategy == "fake_bit_opening" and j == bit_length - 1:
            # Force C_{k-1}^(2^{k-1}) * partial_product == c_shifted
            # by setting C_{k-1} to the non-bit commitment, then forging e0/s0
            cj, _ = group.commit(bits[j], bit_blindings[j])
            bp = _prove_bit_or(
                bit=bits[j],
                bit_blinding=bit_blindings[j],
                bit_commitment=cj,
                parent_shifted_commitment=c_shifted,
                bit_index=j,
                context=context,
                group=group,
            )
            # Tamper with bit_commitment so homomorphic product would match a different value
            tampered_cj = group.add_commitments(cj, group.g)
            bp = BitOrProof(
                bit_index=bp.bit_index,
                bit_commitment=tampered_cj,
                t0=bp.t0,
                t1=bp.t1,
                e0=bp.e0,
                e1=bp.e1,
                s0=bp.s0,
                s1=bp.s1,
            )
        else:
            cj, _ = group.commit(bits[j], bit_blindings[j])
            bp = _prove_bit_or(
                bit=bits[j],
                bit_blinding=bit_blindings[j],
                bit_commitment=cj,
                parent_shifted_commitment=c_shifted,
                bit_index=j,
                context=context,
                group=group,
            )
            partial_product = group.add_commitments(partial_product, group.mul(cj, 1 << j))
        bit_proofs.append(bp)

    return RangeProof(
        commitment=c_actual,
        shifted_commitment=c_shifted,
        lower_bound=lower_bound,
        bit_length=bit_length,
        bit_proofs=bit_proofs,
        context=context,
    )
