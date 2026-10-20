# PQC-Hybrid-KMS-Mesh: Quantum-Safe Key Management & QKD Distribution Architecture

[![CI](https://github.com/FelipeMadson/pqc-hybrid-kms-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMadson/pqc-hybrid-kms-mesh/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-darkblue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20(ML--DSA)-darkblue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![ETSI GS QKD 014](https://img.shields.io/badge/ETSI-GS%20QKD%20014-purple.svg)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/)

> **Reference Prototype engineered for RNP DPDI Chamada PCI 2026 — Projeto 2: *Arquitetura Multidomínio para Redes Quanticamente Seguras*.**

## 📄 Academic Research Paper
- 📑 **Scientific Paper (SBC/RNP Standard)**: [Read the full research paper on Hybrid PQC-QKD (PT-BR)](docs/paper/README.md)

---

## 1. Overview

With the advancement of quantum computing, classical asymmetric cryptographic systems based on integer factorization (RSA) and discrete logarithms over elliptic curves (ECDH, ECDSA, Ed25519) are fundamentally vulnerable to polynomial-time attacks via Shor's algorithm.

**PQC-Hybrid-KMS-Mesh** delivers a multidomain, quantum-resistant key management service and optical network distribution mesh:
1. **Dual-Layer Hybrid Key Encapsulation (Hybrid KEM)**: Combines classical X25519 with lattice-based **ML-KEM-768 (CRYSTALS-Kyber / NIST FIPS 203)**, derived via HKDF-SHA256.
2. **Dual-Layer Hybrid Digital Signatures (Hybrid DSA)**: Combines classical Ed25519 with lattice-based **ML-DSA-65 (CRYSTALS-Dilithium / NIST FIPS 204)** for tamper-proof control planes.
3. **ETSI GS QKD 014 Standard REST Interface**: Fully compliant API delivering quantum session keys between Secure Application Entities (SAEs) and Key Management Systems (KMS).
4. **Multidomain PoP Mesh Coordination**: Key state management and lifecycle rotation across RNP Points of Presence (PoPs).

---

## 2. API Endpoints

| Endpoint | Method | Specification | Description |
|---|---|---|---|
| `/healthz` | `GET` | System | Health and active cryptographic suites |
| `/api/v1/pqc/status` | `GET` | KMS | Local domain status and QKD buffer capacity |
| `/api/v1/pqc/public-key` | `GET` | KMS | Node's hybrid classical + lattice public keys |
| `/api/v1/kem/encapsulate` | `POST` | NIST FIPS 203 | Encapsulates hybrid shared secret |
| `/api/v1/keys/status` | `GET` | ETSI QKD 014 | Buffer status and key availability |
| `/api/v1/keys/enc_keys` | `GET` | ETSI QKD 014 | Delivers quantum keys to Master SAE |
| `/api/v1/keys/dec_keys` | `POST` | ETSI QKD 014 | Retrieves corresponding keys for Slave SAE |

---

## 3. Quickstart

```bash
git clone https://github.com/FelipeMadson/pqc-hybrid-kms-mesh.git
cd pqc-hybrid-kms-mesh
go test -v -race ./...
go run ./cmd/server
```

## License
MIT License (c) 2026 Felipe Madison.
