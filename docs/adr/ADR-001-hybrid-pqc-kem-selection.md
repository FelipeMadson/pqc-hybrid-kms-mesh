# ADR-001: Hybrid Post-Quantum Key Encapsulation (X25519 + ML-KEM-768)

## Status
Accepted

## Context
Under RNP Chamada PCI 2026 (Projeto 2: Arquitetura Multidomínio para Redes Quanticamente Seguras), the RNP optical backbone (Rede Ipê) requires cryptographic mechanisms resilient against quantum adversaries executing Shor's and Grover's algorithms ("Harvest Now, Decrypt Later" threat).

Deploying purely post-quantum algorithms without classical backup introduces operational risk because lattice-based cryptography is relatively recent in global production.

## Decision
We implement a **Dual-Layer Hybrid Key Encapsulation Mechanism (Hybrid KEM)**:
- Classical Layer: X25519 (ECDH on Curve25519, RFC 7748).
- Post-Quantum Layer: ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203).
- Key Derivation: Shared secrets from both mechanisms are combined via HKDF-SHA256:
  $$K_{\text{hybrid}} = \text{HKDF}(\text{IKM} = SS_{\text{classic}} \parallel SS_{\text{lattice}}, \text{info} = \text{"RNP-PQC-HYBRID-KEM"})$$

Security is preserved as long as at least one of the underlying mathematical problems (Elliptic Curve Discrete Logarithm or Learning With Errors over Module Lattices) remains intractable.

## Consequences
- Guaranteed post-quantum security without sacrificing classical compliance.
- Sub-millisecond encapsulation latency suitable for real-time SDN control planes.
