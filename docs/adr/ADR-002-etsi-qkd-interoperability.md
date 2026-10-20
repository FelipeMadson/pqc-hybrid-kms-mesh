# ADR-002: ETSI GS QKD 014 REST Interface Implementation

## Status
Accepted

## Context
Integration of physical Quantum Key Distribution (QKD) hardware (such as optical fibers running BB84 protocol or continuous-variable QKD) with Key Management Systems (KMS) requires a standardized interface. ETSI GS QKD 014 defines the globally recognized REST API between Secure Application Entities (SAE) and Key Management Systems.

## Decision
We implement a fully compliant **ETSI GS QKD 014 REST interface**:
- `GET /api/v1/keys/{slave_SAE_ID}/status`: Real-time key buffer occupancy, key bit length, and transaction rates.
- `GET /api/v1/keys/{slave_SAE_ID}/enc_keys`: Secure delivery of quantum session keys to the master SAE.
- `POST /api/v1/keys/{master_SAE_ID}/dec_keys`: Correlated key retrieval for slave SAE decapsulation.

## Consequences
- Native interoperability with commercial and academic QKD devices deployed in Brazilian academic testbeds.
- Hardware-independent simulation capabilities allowing end-to-end integration testing without physical quantum optical links.
