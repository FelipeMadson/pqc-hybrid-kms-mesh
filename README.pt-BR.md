# PQC-Hybrid-KMS-Mesh: Arquitetura Multidomínio de Gerenciamento de Chaves Quanticamente Seguras e QKD

[![CI](https://github.com/FelipeMadson/pqc-hybrid-kms-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMadson/pqc-hybrid-kms-mesh/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-darkblue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20(ML--DSA)-darkblue.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![ETSI GS QKD 014](https://img.shields.io/badge/ETSI-GS%20QKD%20014-purple.svg)](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/)

> **Protótipo de Referência desenvolvido para a Chamada PCI/CNPq da RNP 2026 — Projeto 2: *Arquitetura Multidomínio para Redes Quanticamente Seguras*.**

## 📄 Artigo Científico
- 📑 **Artigo Científico Completo (Normas SBC/RNP)**: [Ler artigo de pesquisa completo sobre PQC-QKD Híbrido](docs/paper/README.md)

---

## 1. Visão Geral

Com a evolução dos computadores quânticos, os algoritmos assimétricos tradicionais baseados em fatoração de inteiros (RSA) e logaritmos discretos em curvas elípticas (ECDH, Ed25519) tornam-se vulneráveis ao Algoritmo de Shor.

O **PQC-Hybrid-KMS-Mesh** provê uma infraestrutura de gerenciamento de chaves resiliente a ameaças pós-quânticas para os Pontos de Presença (PoPs) do backbone nacional da RNP:
1. **Encapsulamento Híbrido de Chaves (Hybrid KEM)**: Combinação da criptografia clássica X25519 com o padrão em reticulados **ML-KEM-768 (CRYSTALS-Kyber / NIST FIPS 203)** via derivação HKDF-SHA256.
2. **Assinaturas Digitais Híbridas (Hybrid DSA)**: Autenticação de camada de controle via Ed25519 e **ML-DSA-65 (CRYSTALS-Dilithium / NIST FIPS 204)**.
3. **Interface REST ETSI GS QKD 014**: Entrega padronizada de chaves quânticas entre Entidades de Aplicação Seguras (SAEs) e Sistemas de Gerenciamento de Chaves (KMS).
4. **Coordenação Multidomínio**: Ciclo de vida e rotação periódica de chaves entre PoPs regionais.

---

## 2. Execução Local

```bash
git clone https://github.com/FelipeMadson/pqc-hybrid-kms-mesh.git
cd pqc-hybrid-kms-mesh
go test -v -race ./...
go run ./cmd/server
```

## Licença
Licença MIT (c) 2026 Felipe Madison.
