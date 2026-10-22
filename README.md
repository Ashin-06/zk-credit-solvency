# Project 12: Zero-Knowledge Credit Underwriting & Cryptographic Proof-of-Solvency Engine (`zkcredit`)

A zero-knowledge cryptographic engine for **Open Banking (Account Aggregator)** credit underwriting and **Neo-Bank Proof of Solvency**, built from first principles using **Pedersen Commitments**, **Cramer-Damgård-Schoenmakers (CDS) 1-of-2 OR-Sigma Bit-Decomposition Range Proofs**, and **Merkle-Sum Commitment Trees (MSCT)** over a 256-bit Safe Prime group.

---

## Cryptographic Architecture

1. **Prime-Order Pedersen Commitment Group (`zkcredit/crypto.py`)**
   - Safe prime $p = 2q + 1$ ($256$-bit $p$, $255$-bit Sophie Germain prime $q$).
   - Independent generators $g, h \in \mathbb{G}_q$ of prime order $q$, where $h$ is derived via nothing-up-my-sleeve SHA-256 hash-to-group so $\log_g(h)$ is unknown.
   - Homomorphic commitment $C(v, r) = g^v h^r \bmod p$:
     $$C(v_1, r_1) \cdot C(v_2, r_2) \equiv C(v_1 + v_2, r_1 + r_2) \pmod p$$
     $$C(v, r)^k \equiv C(k \cdot v, k \cdot r) \pmod p$$
   - Fiat-Shamir non-interactive Schnorr proofs of opening $(v, r)$, zero-commitment opening, and commitment equality.

2. **Bit-Decomposition CDS 1-of-2 OR-Sigma Range Proofs (`zkcredit/range_proof.py`)**
   - Proves $v - \tau \in [0, 2^k)$ on the shifted commitment $C' = C(v, r) \cdot g^{-\tau} \bmod p$:
     - Commits to each bit $b_j \in \{0, 1\}$ via $C_j = g^{b_j} h^{r_j} \bmod p$ with $\sum_{j=0}^{k-1} 2^j r_j \equiv r \pmod q$, ensuring $\prod_{j=0}^{k-1} C_j^{2^j} \equiv C' \pmod p$.
     - Proves $b_j \in \{0, 1\}$ for every bit $j$ using a 1-of-2 Cramer-Damgård-Schoenmakers OR-Sigma proof via Fiat-Shamir.

3. **Zero-Knowledge Open-Banking Credit Underwriting (`zkcredit/underwrite.py`)**
   - From 12 months of Account Aggregator attested commitments $(C(I_m), C(D_m), C(B_m))$, proves without revealing any Rupee values:
     - **Annual Net Disposable Cashflow**: $\sum_{m=1}^{12} (I_m - D_m) \ge \tau_{\text{net}}$
     - **Debt-to-Income Ratio Cap**: $100 \sum_{m=1}^{12} D_m \le \text{max\_dti\_pct} \cdot \sum_{m=1}^{12} I_m$ via a range proof on $C_{\text{income}}^{\text{max\_dti\_pct}} \cdot C_{\text{debt}}^{-100} \bmod p$
     - **Zero Overdraft / EOD Floor**: $B_m \ge \tau_{\text{min}}$ for all $m \in \{1, \dots, 12\}$

4. **Merkle-Sum Commitment Tree Proof of Solvency (`zkcredit/solvency.py`)**
   - Each customer leaf $i$ commits to balance $b_i \ge 0$ via $C_i = g^{b_i} h^{r_i} \bmod p$ + non-negativity range proof.
   - Internal nodes homomorphically multiply commitments $C_{\text{parent}} = C_L \cdot C_R \bmod p$ up to $C_{\text{root}} = C(\sum b_i, \sum r_i)$.
   - Bank proves $\text{Reserves} - \sum b_i \ge 0$ via a range proof on $C_{\text{reserves}} \cdot C_{\text{root}}^{-1} \bmod p$.
   - Customers verify their $O(\log N)$ inclusion path and sibling non-negativity proofs without seeing any other customer's balance.

---

## Quickstart

```bash
# Run test suite
python -m pytest -q

# Run completeness & soundness benchmark
python -m zkcredit bench

# Launch FastAPI server & interactive console on port 8012
python -m zkcredit serve --port 8012
```
