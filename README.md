# AegisMCP v3.0.1 - Security Suite

AegisMCP v3.0.1 is a production-hardened security suite for the Model Context Protocol (MCP). It features an advanced Bidirectional Anti-Evasion Runtime Proxy, real-time live server inspection, and rigorous integrity verification.

## Core Security Features (v3.0.1)

### Bidirectional Anti-Evasion Runtime Proxy
- **Real-time Threat Inspection**: AMCP309-compliant runtime proxy inspects all traffic between MCP clients and servers.
- **Anti-Evasion Normalizer**: Multi-stage pipeline (Unicode NFKC, iterative URL/Base64/Hex decoding) to expose hidden injection attempts.
- **Weighted Prompt Injection Scoring**: Configurable `STRICT` or `BALANCED` modes via `proxy-policy.yaml`.
- **SSRF Defense**: Deep inspection of internal IP variants (decimal, hex, octal, IPv6-mapped).

### Live MCP Server Introspection (`inspect` command)
- Real-time security audit of running MCP servers (stdio or HTTP/SSE).
- Automatic detection of:
  - **AMCP005**: Tool poisoning patterns in descriptions.
  - **AMCP007**: Hidden invisible Unicode characters.
  - **AMCP203**: Over-permissive tool input schemas (missing constraints).
  - **AMCP201**: Tool name shadowing across servers.

### Integrity & Rug-Pull Protection (`lock`/`verify`)
- **Live Lockfiles**: Create cryptographic hashes (SHA-256) of live tool definitions to detect unauthorized server changes at runtime.
- **CI/CD Integration**: Gated CI pipelines with `--fail-on` thresholds to prevent deployment of insecure server configurations.

---

## Migration to v3.0.1

AegisMCP v3.0.1 maintains full backward compatibility while introducing the new Runtime Proxy and AMCP309 scanning features.

### Quick Start
```bash
# Live Introspection (detect vulnerabilities in running servers)
aegismcp inspect --command "python my_server.py"

# Runtime Proxy (active firewall protection)
aegismcp proxy --command "python my_server.py" --policy proxy-policy.yaml
```

*For detailed documentation, configuration settings, and rule descriptions, please refer to the [CHANGELOG.md](CHANGELOG.md).*
