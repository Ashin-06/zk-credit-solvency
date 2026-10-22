"""
Merkle-Sum Commitment Tree (MSCT) for Cryptographic Neo-Bank Proof of Solvency.

Architecture:
- Each customer leaf i has balance b_i >= 0, blinding r_i in Z_q, and Pedersen commitment
  C_i = g^(b_i) * h^(r_i) mod p, paired with a zero-knowledge RangeProof proving b_i in [0, 2^k).
- Leaf hash: H_i = SHA256("zkcredit.msct.leaf.v1" || user_hash_i || hex(C_i)).
- Internal nodes homomorphically multiply child commitments:
    C_parent = C_L * C_R mod p = g^(b_L + b_R) * h^(r_L + r_R) mod p
  and hash:
    H_parent = SHA256("zkcredit.msct.node.v1" || H_L || hex(C_L) || H_R || hex(C_R) || hex(C_parent)).
- Root commitment C_root commits to total customer liabilities L = sum_i b_i.
- The bank commits to its liquid reserves R via C_reserves = g^R * h^(r_reserves) mod p
  and proves Solvency (R - L >= 0) in zero knowledge using a RangeProof on the homomorphic
  quotient C_surplus = C_reserves * C_root^(-1) mod p = C(R - L, r_reserves - r_root).
- Any customer can verify their O(log N) Merkle-Sum inclusion path and sibling non-negativity
  proofs without seeing any other customer's balance.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from .crypto import DEFAULT_GROUP, PedersenGroup
from .range_proof import (
    RangeProof,
    forge_range_proof_attempt,
    prove_range,
    verify_range,
)

SOLVENCY_BIT_LENGTH = 28  # Supports individual and aggregate balances up to ~26.8 Crore INR


def compute_user_hash(user_id: str, salt: str = "zkcredit.neobank.v1") -> str:
    """Computes privacy-preserving leaf identifier hash H(salt || user_id)."""
    return hashlib.sha256(f"{salt}|{user_id}".encode("utf-8")).hexdigest()


def compute_leaf_hash(user_hash: str, commitment: int) -> str:
    """Computes leaf hash H("zkcredit.msct.leaf.v1" || user_hash || hex(C_i))."""
    payload = f"zkcredit.msct.leaf.v1|{user_hash}|{hex(commitment)}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compute_node_hash(
    left_hash: str,
    left_commitment: int,
    right_hash: str,
    right_commitment: int,
    parent_commitment: int,
) -> str:
    """Computes internal node hash binding both child hashes and homomorphic commitments."""
    payload = (
        f"zkcredit.msct.node.v1|{left_hash}|{hex(left_commitment)}|"
        f"{right_hash}|{hex(right_commitment)}|{hex(parent_commitment)}"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class CustomerAccount:
    """Private customer liability record held by the neo-bank."""

    user_id: str
    balance: int

    def to_dict(self) -> Dict[str, Any]:
        return {"user_id": self.user_id, "balance": self.balance}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CustomerAccount":
        return cls(user_id=str(data["user_id"]), balance=int(data["balance"]))


@dataclass(frozen=True)
class LeafCommitmentNode:
    """Public leaf node in the Merkle-Sum Commitment Tree."""

    leaf_index: int
    user_hash: str
    commitment: int
    node_hash: str
    range_proof: RangeProof

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leaf_index": self.leaf_index,
            "user_hash": self.user_hash,
            "commitment": hex(self.commitment),
            "node_hash": self.node_hash,
            "range_proof": self.range_proof.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LeafCommitmentNode":
        return cls(
            leaf_index=int(data["leaf_index"]),
            user_hash=str(data["user_hash"]),
            commitment=int(str(data["commitment"]), 0),
            node_hash=str(data["node_hash"]),
            range_proof=RangeProof.from_dict(data["range_proof"]),
        )


@dataclass(frozen=True)
class InclusionStep:
    """Single level step in a customer's O(log N) Merkle-Sum inclusion proof."""

    level: int
    sibling_position: str  # "L" if sibling is left child, "R" if sibling is right child
    sibling_hash: str
    sibling_commitment: int
    sibling_nonneg_proof: RangeProof
    parent_commitment: int
    parent_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "sibling_position": self.sibling_position,
            "sibling_hash": self.sibling_hash,
            "sibling_commitment": hex(self.sibling_commitment),
            "sibling_nonneg_proof": self.sibling_nonneg_proof.to_dict(),
            "parent_commitment": hex(self.parent_commitment),
            "parent_hash": self.parent_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InclusionStep":
        return cls(
            level=int(data["level"]),
            sibling_position=str(data["sibling_position"]),
            sibling_hash=str(data["sibling_hash"]),
            sibling_commitment=int(str(data["sibling_commitment"]), 0),
            sibling_nonneg_proof=RangeProof.from_dict(data["sibling_nonneg_proof"]),
            parent_commitment=int(str(data["parent_commitment"]), 0),
            parent_hash=str(data["parent_hash"]),
        )


@dataclass(frozen=True)
class CustomerInclusionProof:
    """
    O(log N) zero-knowledge Merkle-Sum inclusion proof allowing a single customer to verify:
      1. Their exact balance b_i and secret blinding r_i open their leaf commitment C_i.
      2. Every sibling commitment along the path to C_root commits to a non-negative balance.
      3. Every parent commitment along the path is the homomorphic product C_L * C_R mod p.
      4. The path terminates at the published (root_hash, root_commitment).
    """

    user_id: str
    user_hash: str
    leaf_index: int
    claimed_balance: int
    leaf_blinding: int
    leaf_commitment: int
    leaf_hash: str
    leaf_range_proof: RangeProof
    path: List[InclusionStep]
    root_hash: str
    root_commitment: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "user_hash": self.user_hash,
            "leaf_index": self.leaf_index,
            "claimed_balance": self.claimed_balance,
            "leaf_blinding": hex(self.leaf_blinding),
            "leaf_commitment": hex(self.leaf_commitment),
            "leaf_hash": self.leaf_hash,
            "leaf_range_proof": self.leaf_range_proof.to_dict(),
            "path": [step.to_dict() for step in self.path],
            "root_hash": self.root_hash,
            "root_commitment": hex(self.root_commitment),
        }


@dataclass(frozen=True)
class _InternalTreeNode:
    level: int
    index: int
    balance_sum: int
    blinding_sum: int
    commitment: int
    node_hash: str
    range_proof: RangeProof | None = None


@dataclass(frozen=True)
class SolvencyProofBundle:
    """
    Public Neo-Bank Proof-of-Solvency bundle containing the Merkle-Sum Commitment Tree,
    leaf non-negativity range proofs, reserve commitment, and zero-knowledge surplus proof.
    """

    bank_id: str
    num_customers: int
    padded_leaves_count: int
    tree_depth: int
    root_hash: str
    c_total_liabilities: int
    c_reserves: int
    c_surplus: int
    leaves: List[LeafCommitmentNode]
    tree_levels_hashes: List[List[str]]
    tree_levels_commitments: List[List[int]]
    reserve_surplus_proof: RangeProof
    sample_inclusion_proof: CustomerInclusionProof
    generation_ms: float

    def total_proof_bytes(self) -> int:
        leaf_bytes = sum(leaf.range_proof.byte_size() + 64 for leaf in self.leaves)
        surplus_bytes = self.reserve_surplus_proof.byte_size() + 96
        return leaf_bytes + surplus_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bank_id": self.bank_id,
            "num_customers": self.num_customers,
            "padded_leaves_count": self.padded_leaves_count,
            "tree_depth": self.tree_depth,
            "root_hash": self.root_hash,
            "c_total_liabilities": hex(self.c_total_liabilities),
            "c_reserves": hex(self.c_reserves),
            "c_surplus": hex(self.c_surplus),
            "leaves": [leaf.to_dict() for leaf in self.leaves],
            "tree_levels_hashes": self.tree_levels_hashes,
            "tree_levels_commitments": [
                [hex(c) for c in level] for level in self.tree_levels_commitments
            ],
            "reserve_surplus_proof": self.reserve_surplus_proof.to_dict(),
            "sample_inclusion_proof": self.sample_inclusion_proof.to_dict(),
            "generation_ms": round(self.generation_ms, 3),
            "total_proof_bytes": self.total_proof_bytes(),
        }


@dataclass(frozen=True)
class SolvencyAuditResult:
    """Verification result for a Neo-Bank Proof-of-Solvency bundle."""

    bank_id: str
    verified: bool
    all_leaves_nonnegative: bool
    invalid_leaf_indices: List[int]
    merkle_sum_tree_consistent: bool
    reserve_surplus_verified: bool
    sample_inclusion_verified: bool
    tree_depth: int
    total_proof_bytes: int
    verification_ms: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bank_id": self.bank_id,
            "verified": self.verified,
            "all_leaves_nonnegative": self.all_leaves_nonnegative,
            "invalid_leaf_indices": self.invalid_leaf_indices,
            "merkle_sum_tree_consistent": self.merkle_sum_tree_consistent,
            "reserve_surplus_verified": self.reserve_surplus_verified,
            "sample_inclusion_verified": self.sample_inclusion_verified,
            "tree_depth": self.tree_depth,
            "total_proof_bytes": self.total_proof_bytes,
            "verification_ms": round(self.verification_ms, 3),
            "reason": self.reason,
        }


def build_solvency_proof(
    bank_id: str,
    accounts: Sequence[CustomerAccount],
    liquid_reserves: int,
    sample_user_index: int = 0,
    allow_forged: bool = False,
    bit_length: int = SOLVENCY_BIT_LENGTH,
    group: PedersenGroup = DEFAULT_GROUP,
) -> SolvencyProofBundle:
    """
    Builds a Merkle-Sum Commitment Tree from customer accounts and generates a
    zero-knowledge Proof of Solvency (`liquid_reserves - sum(balances) >= 0`).
    """
    if len(accounts) == 0:
        raise ValueError("At least 1 customer account is required.")

    t0 = time.perf_counter()
    num_customers = len(accounts)
    padded_count = 1 << max(1, math.ceil(math.log2(num_customers)))
    tree_depth = int(math.log2(padded_count))

    padded_accounts: List[CustomerAccount] = list(accounts)
    for pad_idx in range(num_customers, padded_count):
        padded_accounts.append(CustomerAccount(user_id=f"__pad_{pad_idx}__", balance=0))

    leaves: List[LeafCommitmentNode] = []
    level0_nodes: List[_InternalTreeNode] = []
    leaf_blindings: List[int] = []

    for i, acct in enumerate(padded_accounts):
        u_hash = compute_user_hash(acct.user_id)
        c_i, r_i = group.commit(acct.balance)
        leaf_blindings.append(r_i)
        l_hash = compute_leaf_hash(u_hash, c_i)
        leaf_ctx = f"{bank_id}|leaf_{i}|{u_hash}"

        if acct.balance >= 0:
            l_proof = prove_range(
                value=acct.balance,
                blinding=r_i,
                commitment=c_i,
                lower_bound=0,
                bit_length=bit_length,
                context=leaf_ctx,
                group=group,
            )
        elif allow_forged:
            l_proof = forge_range_proof_attempt(
                actual_value=acct.balance,
                blinding=r_i,
                lower_bound=0,
                bit_length=bit_length,
                context=leaf_ctx,
                group=group,
            )
        else:
            raise ValueError(
                f"Customer {acct.user_id} at index {i} has negative balance {acct.balance}."
            )

        leaves.append(
            LeafCommitmentNode(
                leaf_index=i,
                user_hash=u_hash,
                commitment=c_i,
                node_hash=l_hash,
                range_proof=l_proof,
            )
        )
        level0_nodes.append(
            _InternalTreeNode(
                level=0,
                index=i,
                balance_sum=acct.balance,
                blinding_sum=r_i,
                commitment=c_i,
                node_hash=l_hash,
                range_proof=l_proof,
            )
        )

    # Build internal tree levels bottom-up via homomorphic commitment multiplication
    all_levels: List[List[_InternalTreeNode]] = [level0_nodes]
    current_level = level0_nodes
    lvl = 1
    while len(current_level) > 1:
        next_level: List[_InternalTreeNode] = []
        for idx in range(0, len(current_level), 2):
            left = current_level[idx]
            right = current_level[idx + 1]
            parent_bal = left.balance_sum + right.balance_sum
            parent_blind = (left.blinding_sum + right.blinding_sum) % group.q
            parent_comm = group.add_commitments(left.commitment, right.commitment)
            parent_hash = compute_node_hash(
                left.node_hash,
                left.commitment,
                right.node_hash,
                right.commitment,
                parent_comm,
            )
            next_level.append(
                _InternalTreeNode(
                    level=lvl,
                    index=idx // 2,
                    balance_sum=parent_bal,
                    blinding_sum=parent_blind,
                    commitment=parent_comm,
                    node_hash=parent_hash,
                )
            )
        all_levels.append(next_level)
        current_level = next_level
        lvl += 1

    root_node = all_levels[-1][0]
    total_liabilities = root_node.balance_sum
    r_total_liabilities = root_node.blinding_sum
    c_total_liabilities = root_node.commitment

    # Commit to bank reserves R and compute homomorphic surplus commitment C_reserves * C_root^(-1)
    c_reserves, r_reserves = group.commit(liquid_reserves)
    c_surplus = group.sub_commitments(c_reserves, c_total_liabilities)
    r_surplus = (r_reserves - r_total_liabilities) % group.q
    surplus_val = liquid_reserves - total_liabilities
    surplus_ctx = f"{bank_id}|reserve_surplus|{root_node.node_hash}"

    if surplus_val >= 0:
        surplus_proof = prove_range(
            value=surplus_val,
            blinding=r_surplus,
            commitment=c_surplus,
            lower_bound=0,
            bit_length=bit_length,
            context=surplus_ctx,
            group=group,
        )
    elif allow_forged:
        surplus_proof = forge_range_proof_attempt(
            actual_value=surplus_val,
            blinding=r_surplus,
            lower_bound=0,
            bit_length=bit_length,
            context=surplus_ctx,
            group=group,
        )
    else:
        raise ValueError(
            f"Bank is insolvent: reserves ({liquid_reserves}) < total liabilities ({total_liabilities})."
        )

    # Extract O(log N) inclusion proof for `sample_user_index`
    target_idx = max(0, min(sample_user_index, num_customers - 1))
    path: List[InclusionStep] = []
    curr_idx = target_idx
    for level_idx in range(tree_depth):
        level_nodes = all_levels[level_idx]
        parent_nodes = all_levels[level_idx + 1]
        is_right_child = (curr_idx % 2) == 1
        sib_idx = curr_idx - 1 if is_right_child else curr_idx + 1
        sib_pos = "L" if is_right_child else "R"
        sib_node = level_nodes[sib_idx]
        parent_node = parent_nodes[curr_idx // 2]

        # Generate or reuse zero-knowledge non-negativity proof for the sibling subtree commitment
        sib_ctx = f"{bank_id}|sibling_L{level_idx}_I{sib_idx}|{sib_node.node_hash}"
        if sib_node.balance_sum >= 0:
            sib_proof = prove_range(
                value=sib_node.balance_sum,
                blinding=sib_node.blinding_sum,
                commitment=sib_node.commitment,
                lower_bound=0,
                bit_length=bit_length,
                context=sib_ctx,
                group=group,
            )
        elif allow_forged:
            sib_proof = forge_range_proof_attempt(
                actual_value=sib_node.balance_sum,
                blinding=sib_node.blinding_sum,
                lower_bound=0,
                bit_length=bit_length,
                context=sib_ctx,
                group=group,
            )
        else:
            raise ValueError("Negative sibling subtree balance encountered.")

        path.append(
            InclusionStep(
                level=level_idx,
                sibling_position=sib_pos,
                sibling_hash=sib_node.node_hash,
                sibling_commitment=sib_node.commitment,
                sibling_nonneg_proof=sib_proof,
                parent_commitment=parent_node.commitment,
                parent_hash=parent_node.node_hash,
            )
        )
        curr_idx //= 2

    target_acct = padded_accounts[target_idx]
    target_leaf = leaves[target_idx]
    inclusion_proof = CustomerInclusionProof(
        user_id=target_acct.user_id,
        user_hash=target_leaf.user_hash,
        leaf_index=target_idx,
        claimed_balance=target_acct.balance,
        leaf_blinding=leaf_blindings[target_idx],
        leaf_commitment=target_leaf.commitment,
        leaf_hash=target_leaf.node_hash,
        leaf_range_proof=target_leaf.range_proof,
        path=path,
        root_hash=root_node.node_hash,
        root_commitment=root_node.commitment,
    )

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return SolvencyProofBundle(
        bank_id=bank_id,
        num_customers=num_customers,
        padded_leaves_count=padded_count,
        tree_depth=tree_depth,
        root_hash=root_node.node_hash,
        c_total_liabilities=c_total_liabilities,
        c_reserves=c_reserves,
        c_surplus=c_surplus,
        leaves=leaves,
        tree_levels_hashes=[[n.node_hash for n in lvl_nodes] for lvl_nodes in all_levels],
        tree_levels_commitments=[[n.commitment for n in lvl_nodes] for lvl_nodes in all_levels],
        reserve_surplus_proof=surplus_proof,
        sample_inclusion_proof=inclusion_proof,
        generation_ms=elapsed_ms,
    )


def verify_customer_inclusion(
    proof: CustomerInclusionProof,
    expected_root_hash: str,
    expected_root_commitment: int,
    bank_id: str,
    bit_length: int = SOLVENCY_BIT_LENGTH,
    group: PedersenGroup = DEFAULT_GROUP,
) -> bool:
    """
    Verifies a single customer's O(log N) Merkle-Sum inclusion path and sibling non-negativity
    proofs without accessing any other customer's leaf or balance.
    """
    # 1. Verify customer's own leaf opening and hash
    if compute_user_hash(proof.user_id) != proof.user_hash:
        return False
    if not group.verify_opening(proof.leaf_commitment, proof.claimed_balance, proof.leaf_blinding):
        return False
    if compute_leaf_hash(proof.user_hash, proof.leaf_commitment) != proof.leaf_hash:
        return False

    leaf_ctx = f"{bank_id}|leaf_{proof.leaf_index}|{proof.user_hash}"
    if not verify_range(
        proof=proof.leaf_range_proof,
        expected_commitment=proof.leaf_commitment,
        expected_lower_bound=0,
        expected_bit_length=bit_length,
        context=leaf_ctx,
        group=group,
    ):
        return False

    # 2. Traverse O(log N) sibling path up to the root
    curr_hash = proof.leaf_hash
    curr_comm = proof.leaf_commitment
    curr_idx = proof.leaf_index

    for step in proof.path:
        sib_idx = curr_idx - 1 if step.sibling_position == "L" else curr_idx + 1
        sib_ctx = f"{bank_id}|sibling_L{step.level}_I{sib_idx}|{step.sibling_hash}"
        if not verify_range(
            proof=step.sibling_nonneg_proof,
            expected_commitment=step.sibling_commitment,
            expected_lower_bound=0,
            expected_bit_length=bit_length,
            context=sib_ctx,
            group=group,
        ):
            return False

        if step.sibling_position == "L":
            left_hash, left_comm = step.sibling_hash, step.sibling_commitment
            right_hash, right_comm = curr_hash, curr_comm
        else:
            left_hash, left_comm = curr_hash, curr_comm
            right_hash, right_comm = step.sibling_hash, step.sibling_commitment

        expected_parent_comm = group.add_commitments(left_comm, right_comm)
        if step.parent_commitment != expected_parent_comm:
            return False

        expected_parent_hash = compute_node_hash(
            left_hash, left_comm, right_hash, right_comm, expected_parent_comm
        )
        if step.parent_hash != expected_parent_hash:
            return False

        curr_hash = step.parent_hash
        curr_comm = step.parent_commitment
        curr_idx //= 2

    return curr_hash == expected_root_hash and curr_comm == expected_root_commitment


def verify_solvency_audit(
    bundle: SolvencyProofBundle,
    bit_length: int = SOLVENCY_BIT_LENGTH,
    group: PedersenGroup = DEFAULT_GROUP,
) -> SolvencyAuditResult:
    """
    Executes a full zero-knowledge cryptographic Proof-of-Solvency audit:
      1. Verifies every leaf commitment has a valid RangeProof (b_i >= 0, preventing
         negative balance injection attacks).
      2. Recomputes the entire Merkle-Sum Commitment Tree bottom-up, checking that
         every internal node equals C_L * C_R mod p and hashes match up to C_root.
      3. Verifies C_surplus == C_reserves * C_root^(-1) mod p and verifies the
         zero-knowledge RangeProof that Reserves - TotalLiabilities >= 0.
      4. Verifies the O(log N) sample customer inclusion proof.
    """
    t0 = time.perf_counter()

    invalid_leaves: List[int] = []
    curr_hashes: List[str] = []
    curr_comms: List[int] = []

    for i, leaf in enumerate(bundle.leaves):
        if leaf.leaf_index != i:
            invalid_leaves.append(i)
            continue
        expected_l_hash = compute_leaf_hash(leaf.user_hash, leaf.commitment)
        leaf_ctx = f"{bundle.bank_id}|leaf_{i}|{leaf.user_hash}"
        ok = (
            leaf.node_hash == expected_l_hash
            and verify_range(
                proof=leaf.range_proof,
                expected_commitment=leaf.commitment,
                expected_lower_bound=0,
                expected_bit_length=bit_length,
                context=leaf_ctx,
                group=group,
            )
        )
        if not ok:
            invalid_leaves.append(i)
        curr_hashes.append(leaf.node_hash)
        curr_comms.append(leaf.commitment)

    all_leaves_ok = len(invalid_leaves) == 0 and len(bundle.leaves) == bundle.padded_leaves_count

    # Recompute Merkle-Sum Commitment Tree up to the root
    tree_ok = len(curr_comms) > 0 and (len(curr_comms) & (len(curr_comms) - 1)) == 0
    if tree_ok:
        while len(curr_comms) > 1:
            next_hashes: List[str] = []
            next_comms: List[int] = []
            for idx in range(0, len(curr_comms), 2):
                c_l, c_r = curr_comms[idx], curr_comms[idx + 1]
                h_l, h_r = curr_hashes[idx], curr_hashes[idx + 1]
                c_p = group.add_commitments(c_l, c_r)
                h_p = compute_node_hash(h_l, c_l, h_r, c_r, c_p)
                next_comms.append(c_p)
                next_hashes.append(h_p)
            curr_comms = next_comms
            curr_hashes = next_hashes

        recomputed_root_comm = curr_comms[0]
        recomputed_root_hash = curr_hashes[0]
        tree_ok = (
            recomputed_root_comm == bundle.c_total_liabilities
            and recomputed_root_hash == bundle.root_hash
        )

    # Check reserve surplus commitment and range proof (Reserves - Liabilities >= 0)
    expected_surplus_comm = group.sub_commitments(bundle.c_reserves, bundle.c_total_liabilities)
    surplus_ctx = f"{bundle.bank_id}|reserve_surplus|{bundle.root_hash}"
    surplus_ok = (
        bundle.c_surplus == expected_surplus_comm
        and verify_range(
            proof=bundle.reserve_surplus_proof,
            expected_commitment=expected_surplus_comm,
            expected_lower_bound=0,
            expected_bit_length=bit_length,
            context=surplus_ctx,
            group=group,
        )
    )

    # Check O(log N) customer inclusion proof
    inclusion_ok = verify_customer_inclusion(
        proof=bundle.sample_inclusion_proof,
        expected_root_hash=bundle.root_hash,
        expected_root_commitment=bundle.c_total_liabilities,
        bank_id=bundle.bank_id,
        bit_length=bit_length,
        group=group,
    )

    verified = all_leaves_ok and tree_ok and surplus_ok and inclusion_ok
    reasons: List[str] = []
    if not all_leaves_ok:
        reasons.append(f"Invalid/negative leaf commitment proof(s) at indices {invalid_leaves}")
    if not tree_ok:
        reasons.append("Merkle-Sum Commitment Tree homomorphic invariant or root hash mismatch")
    if not surplus_ok:
        reasons.append("Reserve surplus range proof failed (Reserves < Total Liabilities)")
    if not inclusion_ok:
        reasons.append("Customer O(log N) Merkle-Sum inclusion proof failed")

    reason_str = (
        "Merkle-Sum Commitment Tree and Reserve Surplus verified in zero knowledge."
        if verified
        else "; ".join(reasons)
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return SolvencyAuditResult(
        bank_id=bundle.bank_id,
        verified=verified,
        all_leaves_nonnegative=all_leaves_ok,
        invalid_leaf_indices=invalid_leaves,
        merkle_sum_tree_consistent=tree_ok,
        reserve_surplus_verified=surplus_ok,
        sample_inclusion_verified=inclusion_ok,
        tree_depth=bundle.tree_depth,
        total_proof_bytes=bundle.total_proof_bytes(),
        verification_ms=elapsed_ms,
        reason=reason_str,
    )
