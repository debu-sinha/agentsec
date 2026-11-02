# agentgateway/agentgateway

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-37%2F100-red?style=for-the-badge)

**Repository:** [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway)
**Stars:** 5,876
**Last scan:** 2026-11-02

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟡 Medium | **16** |
| 🟢 Low | **101** |
| 🔵 Info | **1** |
| **Total** | **118** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟡 Medium | Exposed Token | Secret Keyword found in virtualkeys_to_configmap.go | Rotate and secure the Secret Keyword |
| 3 | 🟢 Low | Exposed Token | Base64 High Entropy String found in local_tests.rs | Rotate and secure the Base64 High Entropy String |
| 4 | 🟡 Medium | Exposed Token | Secret Keyword found in traffic_plugin.go | Rotate and secure the Secret Keyword |
| 5 | 🟡 Medium | Exposed Token | Secret Keyword found in traffic_plugin.go | Rotate and secure the Secret Keyword |
| 6 | 🟢 Low | Exposed Token | Private Key found in rsa2049.pem | Rotate and secure the Private Key |
| 7 | 🟢 Low | Exposed Token | Secret Keyword found in tls-spiffe-istio-conflict.yaml | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | JSON Web Token found in example1.key | Rotate and secure the JSON Web Token |
| 9 | 🟢 Low | Exposed Token | Private Key found in key.pem | Rotate and secure the Private Key |
| 10 | 🟢 Low | Exposed Token | JSON Web Token found in remote.go | Rotate and secure the JSON Web Token |
| 11 | 🟢 Low | Exposed Token | Base64 High Entropy String found in remote.go | Rotate and secure the Base64 High Entropy String |
| 12 | 🟢 Low | Exposed Token | Base64 High Entropy String found in remote.go | Rotate and secure the Base64 High Entropy String |
| 13 | 🟢 Low | Exposed Token | JSON Web Token found in remote.go | Rotate and secure the JSON Web Token |
| 14 | 🟢 Low | Exposed Token | JSON Web Token found in remote.go | Rotate and secure the JSON Web Token |
| 15 | 🟢 Low | Exposed Token | Base64 High Entropy String found in remote.go | Rotate and secure the Base64 High Entropy String |
| 16 | 🟢 Low | Exposed Token | Base64 High Entropy String found in multi-target-ref-backend-policy.yaml | Rotate and secure the Base64 High Entropy String |
| 17 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-gateway-policy.yaml | Rotate and secure the Base64 High Entropy String |
| 18 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-gateway-policy.yaml | Rotate and secure the Base64 High Entropy String |
| 19 | 🟢 Low | Exposed Token | Secret Keyword found in listenerset-refgrant.yaml | Rotate and secure the Secret Keyword |
| 20 | 🟢 Low | Exposed Token | Secret Keyword found in listenerset-refgrant.yaml | Rotate and secure the Secret Keyword |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in tls.yaml | Rotate and secure the Secret Keyword |
| 22 | 🟢 Low | Exposed Token | Private Key found in ca-key.pem | Rotate and secure the Private Key |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in awsauth.yaml | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in openai-compatible-headers.yaml | Rotate and secure the Secret Keyword |
| 25 | 🟢 Low | Exposed Token | Secret Keyword found in listenerset-https-tls-shared-port.yaml | Rotate and secure the Secret Keyword |
| 26 | 🟢 Low | Exposed Token | Secret Keyword found in multi-gateway-shared-port.yaml | Rotate and secure the Secret Keyword |
| 27 | 🟢 Low | Exposed Token | Base64 High Entropy String found in README.md | Rotate and secure the Base64 High Entropy String |
| 28 | 🟢 Low | Exposed Token | Base64 High Entropy String found in README.md | Rotate and secure the Base64 High Entropy String |
| 29 | 🟢 Low | Exposed Token | Base64 High Entropy String found in README.md | Rotate and secure the Base64 High Entropy String |
| 30 | 🟢 Low | Exposed Token | Private Key found in dynamic-ca-cert.yaml | Rotate and secure the Private Key |
| 31 | 🟢 Low | Exposed Token | JSON Web Token found in dummy_idp.go | Rotate and secure the JSON Web Token |
| 32 | 🟢 Low | Exposed Token | Base64 High Entropy String found in dummy_idp.go | Rotate and secure the Base64 High Entropy String |
| 33 | 🟢 Low | Exposed Token | Secret Keyword found in dummy_idp.go | Rotate and secure the Secret Keyword |
| 34 | 🟢 Low | Exposed Token | Secret Keyword found in dummy_idp.go | Rotate and secure the Secret Keyword |
| 35 | 🟢 Low | Exposed Token | JSON Web Token found in example2.key | Rotate and secure the JSON Web Token |
| 36 | 🟢 Low | Exposed Token | Private Key found in key.pem | Rotate and secure the Private Key |
| 37 | 🟢 Low | Exposed Token | Secret Keyword found in load-balancing-fallbacks.yaml | Rotate and secure the Secret Keyword |
| 38 | 🟢 Low | Exposed Token | Secret Keyword found in load-balancing-fallbacks.yaml | Rotate and secure the Secret Keyword |
| 39 | 🟢 Low | Exposed Token | Secret Keyword found in load-balancing-fallbacks.yaml | Rotate and secure the Secret Keyword |
| 40 | 🟢 Low | Exposed Token | Base64 High Entropy String found in auth.rs | Rotate and secure the Base64 High Entropy String |
| 41 | 🟢 Low | Exposed Token | Private Key found in auth.rs | Rotate and secure the Private Key |
| 42 | 🟢 Low | Exposed Token | Secret Keyword found in auth.rs | Rotate and secure the Secret Keyword |
| 43 | 🟢 Low | Exposed Token | Secret Keyword found in listenerset-https-tls-shared-port-cross-namespace.yaml | Rotate and secure the Secret Keyword |
| 44 | 🟡 Medium | Exposed Token | Secret Keyword found in agentgateway_policy_types.go | Rotate and secure the Secret Keyword |
| 45 | 🟢 Low | Exposed Token | Private Key found in dummy-idp.key | Rotate and secure the Private Key |
| 46 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_conditional_config.yaml | Rotate and secure the Secret Keyword |
| 47 | 🟢 Low | Exposed Token | Secret Keyword found in multi-listener-shared-port.yaml | Rotate and secure the Secret Keyword |
| 48 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 49 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 50 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 51 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 52 | 🟢 Low | Exposed Token | Private Key found in caclient.rs | Rotate and secure the Private Key |
| 53 | 🟢 Low | Exposed Token | Private Key found in caclient.rs | Rotate and secure the Private Key |
| 54 | 🟢 Low | Exposed Token | Secret Keyword found in invalid-tls.yaml | Rotate and secure the Secret Keyword |
| 55 | 🟢 Low | Exposed Token | Secret Keyword found in OpenAI_backend_with_secret_reference_auth.yaml | Rotate and secure the Secret Keyword |
| 56 | 🟢 Low | Exposed Token | Private Key found in auth_server.py | Rotate and secure the Private Key |
| 57 | 🟢 Low | Exposed Token | Base64 High Entropy String found in auth_server.py | Rotate and secure the Base64 High Entropy String |
| 58 | 🟢 Low | Exposed Token | Secret Keyword found in cors.rs | Rotate and secure the Secret Keyword |
| 59 | 🟢 Low | Exposed Token | Private Key found in agent.rs | Rotate and secure the Private Key |
| 60 | 🟢 Low | Exposed Token | Private Key found in agent.rs | Rotate and secure the Private Key |
| 61 | 🟢 Low | Exposed Token | Base64 High Entropy String found in jwt_tests.rs | Rotate and secure the Base64 High Entropy String |
| 62 | 🟢 Low | Exposed Token | Base64 High Entropy String found in jwt_tests.rs | Rotate and secure the Base64 High Entropy String |
| 63 | 🟢 Low | Exposed Token | Base64 High Entropy String found in jwt_tests.rs | Rotate and secure the Base64 High Entropy String |
| 64 | 🟢 Low | Exposed Token | Private Key found in jwt_tests.rs | Rotate and secure the Private Key |
| 65 | 🟢 Low | Exposed Token | Base64 High Entropy String found in jwt_tests.rs | Rotate and secure the Base64 High Entropy String |
| 66 | 🟢 Low | Exposed Token | JSON Web Token found in jwt_tests.rs | Rotate and secure the JSON Web Token |
| 67 | 🟢 Low | Exposed Token | Private Key found in dynamic-ca-cert-invalid-ca.yaml | Rotate and secure the Private Key |
| 68 | 🟢 Low | Exposed Token | JSON Web Token found in function_tests.rs | Rotate and secure the JSON Web Token |
| 69 | 🟢 Low | Exposed Token | JSON Web Token found in function_tests.rs | Rotate and secure the JSON Web Token |
| 70 | 🟢 Low | Exposed Token | Private Key found in tests.rs | Rotate and secure the Private Key |
| 71 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tests.rs | Rotate and secure the Base64 High Entropy String |
| 72 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-gateway-policy-with-rbac.yaml | Rotate and secure the Base64 High Entropy String |
| 73 | 🟢 Low | Exposed Token | Private Key found in tls-secret.yaml | Rotate and secure the Private Key |
| 74 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners-dynamic-ca-cert-frontend-mtls.yaml | Rotate and secure the Secret Keyword |
| 75 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners.yaml | Rotate and secure the Secret Keyword |
| 76 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth.yaml | Rotate and secure the Base64 High Entropy String |
| 77 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth.yaml | Rotate and secure the Base64 High Entropy String |
| 78 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners-cross-ns.yaml | Rotate and secure the Secret Keyword |
| 79 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners-cross-ns.yaml | Rotate and secure the Secret Keyword |
| 80 | 🟢 Low | Exposed Token | Base64 High Entropy String found in fetcher_test.go | Rotate and secure the Base64 High Entropy String |
| 81 | 🟢 Low | Exposed Token | JSON Web Token found in fips.rs | Rotate and secure the JSON Web Token |
| 82 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_provider_reference_config.yaml | Rotate and secure the Secret Keyword |
| 83 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp_tests.rs | Rotate and secure the Base64 High Entropy String |
| 84 | 🟢 Low | Exposed Token | Base64 High Entropy String found in reasoning_omitted.json | Rotate and secure the Base64 High Entropy String |
| 85 | 🟢 Low | Exposed Token | Secret Keyword found in tests.rs | Rotate and secure the Secret Keyword |
| 86 | 🟢 Low | Exposed Token | Private Key found in tests.rs | Rotate and secure the Private Key |
| 87 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tests.rs | Rotate and secure the Base64 High Entropy String |
| 88 | 🟢 Low | Exposed Token | Private Key found in rsa2048.pem | Rotate and secure the Private Key |
| 89 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_config.yaml | Rotate and secure the Secret Keyword |
| 90 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_config.yaml | Rotate and secure the Secret Keyword |
| 91 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-route-with-rbac.yaml | Rotate and secure the Base64 High Entropy String |
| 92 | 🟢 Low | Exposed Token | Secret Keyword found in unmapped-fields.yaml | Rotate and secure the Secret Keyword |
| 93 | 🟢 Low | Exposed Token | Private Key found in ca-key.pem | Rotate and secure the Private Key |
| 94 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-route.yaml | Rotate and secure the Base64 High Entropy String |
| 95 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-route.yaml | Rotate and secure the Base64 High Entropy String |
| 96 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_failover_config.yaml | Rotate and secure the Secret Keyword |
| 97 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_failover_config.yaml | Rotate and secure the Secret Keyword |
| 98 | 🟢 Low | Exposed Token | Private Key found in tests.rs | Rotate and secure the Private Key |
| 99 | 🟢 Low | Exposed Token | Secret Keyword found in environment-references.yaml | Rotate and secure the Secret Keyword |
| 100 | 🟢 Low | Exposed Token | Secret Keyword found in credential-conflicts.yaml | Rotate and secure the Secret Keyword |
| 101 | 🟢 Low | Exposed Token | Secret Keyword found in credential-conflicts.yaml | Rotate and secure the Secret Keyword |
| 102 | 🟢 Low | Exposed Token | Secret Keyword found in credential-conflicts.yaml | Rotate and secure the Secret Keyword |
| 103 | 🟢 Low | Exposed Token | Secret Keyword found in credential-conflicts.yaml | Rotate and secure the Secret Keyword |
| 104 | 🟢 Low | Exposed Token | Base64 High Entropy String found in stream_thinking.json | Rotate and secure the Base64 High Entropy String |
| 105 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth-multi-target.yaml | Rotate and secure the Base64 High Entropy String |
| 106 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth-multi-target.yaml | Rotate and secure the Base64 High Entropy String |
| 107 | 🟢 Low | Exposed Token | Base64 High Entropy String found in stream-image.json | Rotate and secure the Base64 High Entropy String |
| 108 | 🟢 Low | Exposed Token | Secret Keyword found in centralized-credentials.yaml | Rotate and secure the Secret Keyword |
| 109 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 110 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 111 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 112 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 113 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 114 | 🟡 Medium | Exposed Token | Base64 High Entropy String found in ui_oidc_config.yaml | Rotate and secure the Base64 High Entropy String |
| 115 | 🟢 Low | Exposed Token | Private Key found in valid-jwt-sign.yaml | Rotate and secure the Private Key |
| 116 | 🟢 Low | Exposed Token | Private Key found in config.yaml | Rotate and secure the Private Key |
| 117 | 🟡 Medium | Exposed Token | Secret Keyword found in secrets.go | Rotate and secure the Secret Keyword |
| 118 | 🟢 Low | Exposed Token | Secret Keyword found in reference-grant-multiple-to.yaml | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 117 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-11-02 by [agentsec](https://github.com/debu-sinha/agentsec)*
