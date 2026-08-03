# agentgateway/agentgateway

![Grade](https://img.shields.io/badge/Grade-F-red?style=for-the-badge) ![Score](https://img.shields.io/badge/Score-13%2F100-red?style=for-the-badge)

**Repository:** [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway)
**Stars:** 4,189
**Last scan:** 2026-08-03

## Severity Summary

| Severity | Count |
|----------|------:|
| 🟡 Medium | **24** |
| 🟢 Low | **101** |
| 🔵 Info | **1** |
| **Total** | **126** |

## Findings

| # | Severity | Category | Title | Remediation |
|--:|:--------:|----------|-------|-------------|
| 1 | 🔵 Info | Outdated Version | Could not determine agent version | Ensure agent is updated to latest version |
| 2 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_provider_reference_config.yaml | Rotate and secure the Secret Keyword |
| 3 | 🟢 Low | Exposed Token | Secret Keyword found in backend-oauth-realm.json | Rotate and secure the Secret Keyword |
| 4 | 🟢 Low | Exposed Token | Private Key found in tests.rs | Rotate and secure the Private Key |
| 5 | 🟢 Low | Exposed Token | Secret Keyword found in OpenAI_backend_with_secret_reference_auth.yaml | Rotate and secure the Secret Keyword |
| 6 | 🟡 Medium | Exposed Token | Secret Keyword found in route_collections.go | Rotate and secure the Secret Keyword |
| 7 | 🟡 Medium | Exposed Token | Secret Keyword found in filters.go | Rotate and secure the Secret Keyword |
| 8 | 🟢 Low | Exposed Token | Secret Keyword found in listenerset-refgrant.yaml | Rotate and secure the Secret Keyword |
| 9 | 🟢 Low | Exposed Token | Secret Keyword found in listenerset-refgrant.yaml | Rotate and secure the Secret Keyword |
| 10 | 🟢 Low | Exposed Token | Secret Keyword found in apikey-configmap-selector-raw-key-rejected.yaml | Rotate and secure the Secret Keyword |
| 11 | 🟡 Medium | Exposed Token | Secret Keyword found in traffic_plugin.go | Rotate and secure the Secret Keyword |
| 12 | 🟡 Medium | Exposed Token | Secret Keyword found in traffic_plugin.go | Rotate and secure the Secret Keyword |
| 13 | 🟢 Low | Exposed Token | Secret Keyword found in awsauth.yaml | Rotate and secure the Secret Keyword |
| 14 | 🟢 Low | Exposed Token | Base64 High Entropy String found in jwt_tests.rs | Rotate and secure the Base64 High Entropy String |
| 15 | 🟢 Low | Exposed Token | Base64 High Entropy String found in jwt_tests.rs | Rotate and secure the Base64 High Entropy String |
| 16 | 🟢 Low | Exposed Token | Secret Keyword found in tls.yaml | Rotate and secure the Secret Keyword |
| 17 | 🟢 Low | Exposed Token | Private Key found in caclient.rs | Rotate and secure the Private Key |
| 18 | 🟢 Low | Exposed Token | Private Key found in caclient.rs | Rotate and secure the Private Key |
| 19 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-gateway-policy.yaml | Rotate and secure the Base64 High Entropy String |
| 20 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-gateway-policy.yaml | Rotate and secure the Base64 High Entropy String |
| 21 | 🟢 Low | Exposed Token | Secret Keyword found in backend-oauth-realm.json | Rotate and secure the Secret Keyword |
| 22 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_conditional_config.yaml | Rotate and secure the Secret Keyword |
| 23 | 🟢 Low | Exposed Token | Secret Keyword found in multi-gateway-shared-port.yaml | Rotate and secure the Secret Keyword |
| 24 | 🟢 Low | Exposed Token | Secret Keyword found in cors.rs | Rotate and secure the Secret Keyword |
| 25 | 🟡 Medium | Exposed Token | Secret Keyword found in oauth.rs | Rotate and secure the Secret Keyword |
| 26 | 🟡 Medium | Exposed Token | Secret Keyword found in oauth.rs | Rotate and secure the Secret Keyword |
| 27 | 🟡 Medium | Exposed Token | Secret Keyword found in virtualkeys_to_configmap.go | Rotate and secure the Secret Keyword |
| 28 | 🟡 Medium | Exposed Token | Secret Keyword found in agentgateway_policy_types.go | Rotate and secure the Secret Keyword |
| 29 | 🟢 Low | Exposed Token | JSON Web Token found in dummy_idp.go | Rotate and secure the JSON Web Token |
| 30 | 🟢 Low | Exposed Token | Secret Keyword found in dummy_idp.go | Rotate and secure the Secret Keyword |
| 31 | 🟢 Low | Exposed Token | Secret Keyword found in dummy_idp.go | Rotate and secure the Secret Keyword |
| 32 | 🟢 Low | Exposed Token | Base64 High Entropy String found in dummy_idp.go | Rotate and secure the Base64 High Entropy String |
| 33 | 🟢 Low | Exposed Token | Secret Keyword found in MultiPool_backend_-_translates_all_providers_for_failover.yaml | Rotate and secure the Secret Keyword |
| 34 | 🟢 Low | Exposed Token | Secret Keyword found in MultiPool_backend_-_translates_all_providers_for_failover.yaml | Rotate and secure the Secret Keyword |
| 35 | 🟡 Medium | Exposed Token | Secret Keyword found in secrets.go | Rotate and secure the Secret Keyword |
| 36 | 🟢 Low | Exposed Token | Secret Keyword found in gcpauth.yaml | Rotate and secure the Secret Keyword |
| 37 | 🟢 Low | Exposed Token | Base64 High Entropy String found in stream_thinking.json | Rotate and secure the Base64 High Entropy String |
| 38 | 🟢 Low | Exposed Token | Secret Keyword found in unmapped-fields.yaml | Rotate and secure the Secret Keyword |
| 39 | 🟢 Low | Exposed Token | Secret Keyword found in reference-grant-multiple-to.yaml | Rotate and secure the Secret Keyword |
| 40 | 🟢 Low | Exposed Token | Private Key found in dynamic-ca-cert.yaml | Rotate and secure the Private Key |
| 41 | 🟢 Low | Exposed Token | Secret Keyword found in auth.rs | Rotate and secure the Secret Keyword |
| 42 | 🟢 Low | Exposed Token | Secret Keyword found in auth.rs | Rotate and secure the Secret Keyword |
| 43 | 🟢 Low | Exposed Token | Base64 High Entropy String found in auth.rs | Rotate and secure the Base64 High Entropy String |
| 44 | 🟢 Low | Exposed Token | Private Key found in auth.rs | Rotate and secure the Private Key |
| 45 | 🟢 Low | Exposed Token | Private Key found in config.yaml | Rotate and secure the Private Key |
| 46 | 🟢 Low | Exposed Token | Secret Keyword found in MultiPool_backend_with_multiple_priority_levels_-_creates_separate_provider_groups.yaml | Rotate and secure the Secret Keyword |
| 47 | 🟢 Low | Exposed Token | Secret Keyword found in MultiPool_backend_with_multiple_priority_levels_-_creates_separate_provider_groups.yaml | Rotate and secure the Secret Keyword |
| 48 | 🟢 Low | Exposed Token | Secret Keyword found in MultiPool_backend_with_multiple_priority_levels_-_creates_separate_provider_groups.yaml | Rotate and secure the Secret Keyword |
| 49 | 🟢 Low | Exposed Token | JSON Web Token found in remote.go | Rotate and secure the JSON Web Token |
| 50 | 🟢 Low | Exposed Token | JSON Web Token found in remote.go | Rotate and secure the JSON Web Token |
| 51 | 🟢 Low | Exposed Token | Base64 High Entropy String found in remote.go | Rotate and secure the Base64 High Entropy String |
| 52 | 🟢 Low | Exposed Token | Base64 High Entropy String found in remote.go | Rotate and secure the Base64 High Entropy String |
| 53 | 🟢 Low | Exposed Token | Base64 High Entropy String found in remote.go | Rotate and secure the Base64 High Entropy String |
| 54 | 🟢 Low | Exposed Token | JSON Web Token found in remote.go | Rotate and secure the JSON Web Token |
| 55 | 🟢 Low | Exposed Token | JSON Web Token found in example2.key | Rotate and secure the JSON Web Token |
| 56 | 🟢 Low | Exposed Token | Secret Keyword found in invalid-tls.yaml | Rotate and secure the Secret Keyword |
| 57 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-route-with-rbac.yaml | Rotate and secure the Base64 High Entropy String |
| 58 | 🟢 Low | Exposed Token | Secret Keyword found in load-balancing-fallbacks.yaml | Rotate and secure the Secret Keyword |
| 59 | 🟢 Low | Exposed Token | Secret Keyword found in load-balancing-fallbacks.yaml | Rotate and secure the Secret Keyword |
| 60 | 🟢 Low | Exposed Token | Secret Keyword found in load-balancing-fallbacks.yaml | Rotate and secure the Secret Keyword |
| 61 | 🟢 Low | Exposed Token | Secret Keyword found in idp-realm.json | Rotate and secure the Secret Keyword |
| 62 | 🟢 Low | Exposed Token | Secret Keyword found in apikey-pre-routing.yaml | Rotate and secure the Secret Keyword |
| 63 | 🟢 Low | Exposed Token | Private Key found in dynamic-ca-cert-invalid-ca.yaml | Rotate and secure the Private Key |
| 64 | 🟢 Low | Exposed Token | Secret Keyword found in tests.rs | Rotate and secure the Secret Keyword |
| 65 | 🟢 Low | Exposed Token | Private Key found in tests.rs | Rotate and secure the Private Key |
| 66 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tests.rs | Rotate and secure the Base64 High Entropy String |
| 67 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth-multi-target.yaml | Rotate and secure the Base64 High Entropy String |
| 68 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth-multi-target.yaml | Rotate and secure the Base64 High Entropy String |
| 69 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-gateway-policy-with-rbac.yaml | Rotate and secure the Base64 High Entropy String |
| 70 | 🟢 Low | Exposed Token | Private Key found in key.pem | Rotate and secure the Private Key |
| 71 | 🟢 Low | Exposed Token | Base64 High Entropy String found in auth_server.py | Rotate and secure the Base64 High Entropy String |
| 72 | 🟢 Low | Exposed Token | Private Key found in auth_server.py | Rotate and secure the Private Key |
| 73 | 🟡 Medium | Exposed Token | Secret Keyword found in agentgateway.dev_agentgatewaybackends.yaml | Rotate and secure the Secret Keyword |
| 74 | 🟢 Low | Exposed Token | Base64 High Entropy String found in README.md | Rotate and secure the Base64 High Entropy String |
| 75 | 🟢 Low | Exposed Token | Base64 High Entropy String found in README.md | Rotate and secure the Base64 High Entropy String |
| 76 | 🟢 Low | Exposed Token | Base64 High Entropy String found in README.md | Rotate and secure the Base64 High Entropy String |
| 77 | 🟢 Low | Exposed Token | Secret Keyword found in environment-references.yaml | Rotate and secure the Secret Keyword |
| 78 | 🟡 Medium | Exposed Token | Secret Keyword found in config_store.rs | Rotate and secure the Secret Keyword |
| 79 | 🟢 Low | Exposed Token | Secret Keyword found in config.yaml | Rotate and secure the Secret Keyword |
| 80 | 🟢 Low | Exposed Token | Base64 High Entropy String found in fetcher_test.go | Rotate and secure the Base64 High Entropy String |
| 81 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth.yaml | Rotate and secure the Base64 High Entropy String |
| 82 | 🟢 Low | Exposed Token | Base64 High Entropy String found in mcp-auth.yaml | Rotate and secure the Base64 High Entropy String |
| 83 | 🟢 Low | Exposed Token | Secret Keyword found in apikey-secret-selector.yaml | Rotate and secure the Secret Keyword |
| 84 | 🟡 Medium | Exposed Token | Secret Keyword found in conversion.go | Rotate and secure the Secret Keyword |
| 85 | 🟢 Low | Exposed Token | Secret Keyword found in config.yaml | Rotate and secure the Secret Keyword |
| 86 | 🟢 Low | Exposed Token | Private Key found in ca-key.pem | Rotate and secure the Private Key |
| 87 | 🟢 Low | Exposed Token | Private Key found in agent.rs | Rotate and secure the Private Key |
| 88 | 🟢 Low | Exposed Token | Private Key found in agent.rs | Rotate and secure the Private Key |
| 89 | 🟢 Low | Exposed Token | Secret Keyword found in agentgateway-realm.json | Rotate and secure the Secret Keyword |
| 90 | 🟢 Low | Exposed Token | Secret Keyword found in apikey-configmap-selector.yaml | Rotate and secure the Secret Keyword |
| 91 | 🟢 Low | Exposed Token | Private Key found in dummy-idp.key | Rotate and secure the Private Key |
| 92 | 🟡 Medium | Exposed Token | Secret Keyword found in resource.pb.go | Rotate and secure the Secret Keyword |
| 93 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_config.yaml | Rotate and secure the Secret Keyword |
| 94 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_config.yaml | Rotate and secure the Secret Keyword |
| 95 | 🟢 Low | Exposed Token | Base64 High Entropy String found in multi-target-ref-backend-policy.yaml | Rotate and secure the Base64 High Entropy String |
| 96 | 🟢 Low | Exposed Token | JSON Web Token found in function_tests.rs | Rotate and secure the JSON Web Token |
| 97 | 🟢 Low | Exposed Token | JSON Web Token found in function_tests.rs | Rotate and secure the JSON Web Token |
| 98 | 🟢 Low | Exposed Token | Base64 High Entropy String found in stream-image.json | Rotate and secure the Base64 High Entropy String |
| 99 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners-cross-ns.yaml | Rotate and secure the Secret Keyword |
| 100 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners-cross-ns.yaml | Rotate and secure the Secret Keyword |
| 101 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-route.yaml | Rotate and secure the Base64 High Entropy String |
| 102 | 🟢 Low | Exposed Token | Base64 High Entropy String found in secured-route.yaml | Rotate and secure the Base64 High Entropy String |
| 103 | 🟢 Low | Exposed Token | Secret Keyword found in tests.rs | Rotate and secure the Secret Keyword |
| 104 | 🟢 Low | Exposed Token | Base64 High Entropy String found in tests.rs | Rotate and secure the Base64 High Entropy String |
| 105 | 🟢 Low | Exposed Token | Private Key found in tests.rs | Rotate and secure the Private Key |
| 106 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_failover_config.yaml | Rotate and secure the Secret Keyword |
| 107 | 🟡 Medium | Exposed Token | Secret Keyword found in llm_virtual_model_failover_config.yaml | Rotate and secure the Secret Keyword |
| 108 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 109 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 110 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 111 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 112 | 🟢 Low | Exposed Token | JSON Web Token found in jwtauth_test.go | Rotate and secure the JSON Web Token |
| 113 | 🟢 Low | Exposed Token | Secret Keyword found in basic-auth-pre-routing.yaml | Rotate and secure the Secret Keyword |
| 114 | 🟢 Low | Exposed Token | Private Key found in key.pem | Rotate and secure the Private Key |
| 115 | 🟢 Low | Exposed Token | Secret Keyword found in backend-oauth-realm.json | Rotate and secure the Secret Keyword |
| 116 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 117 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 118 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 119 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 120 | 🟡 Medium | Exposed Token | Secret Keyword found in backend_policies.go | Rotate and secure the Secret Keyword |
| 121 | 🟢 Low | Exposed Token | Private Key found in ca-key.pem | Rotate and secure the Private Key |
| 122 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners-dynamic-ca-cert-frontend-mtls.yaml | Rotate and secure the Secret Keyword |
| 123 | 🟢 Low | Exposed Token | JSON Web Token found in example1.key | Rotate and secure the JSON Web Token |
| 124 | 🟢 Low | Exposed Token | Secret Keyword found in tls-listeners.yaml | Rotate and secure the Secret Keyword |
| 125 | 🟢 Low | Exposed Token | Base64 High Entropy String found in local_tests.rs | Rotate and secure the Base64 High Entropy String |
| 126 | 🟢 Low | Exposed Token | Secret Keyword found in multi-listener-shared-port.yaml | Rotate and secure the Secret Keyword |

## Categories

| Category | Count |
|----------|------:|
| Exposed Token | 125 |
| Outdated Version | 1 |

---

[Back to Dashboard](../mcp-security-grades.md) | *Scanned on 2026-08-03 by [agentsec](https://github.com/debu-sinha/agentsec)*
