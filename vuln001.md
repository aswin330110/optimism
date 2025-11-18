# VULN-001: Unauthenticated Admin API in op-node

## Severity
**CRITICAL**

## Component
op-node

## Vulnerability Type
- CWE-306: Missing Authentication for Critical Function
- CWE-284: Improper Access Control

## Description
The op-node admin API exposes critical operational functions without any authentication mechanism. When enabled via `--rpc.enable-admin`, the admin namespace becomes accessible to anyone who can reach the RPC endpoint.

## Affected Code Locations
- `/home/user/optimism/op-node/node/api.go` lines 49-103
- `/home/user/optimism/op-node/node/node.go` lines 477-482

## Vulnerable Functions
The following critical functions are exposed without authentication:

1. **`admin_postUnsafePayload`** (line 81-89): Allows posting unsafe L2 payloads directly to the derivation pipeline
   - Intended only for op-conductor failover scenarios
   - Could be used to inject malicious or invalid payloads

2. **`admin_startSequencer`** (line 67-69): Starts the sequencer
   - Can cause the node to begin producing blocks

3. **`admin_stopSequencer`** (line 71-73): Stops the sequencer
   - Denial of service vector

4. **`admin_resetDerivationPipeline`** (line 63-65): Resets the entire derivation pipeline
   - Could cause state inconsistencies

5. **`admin_overrideLeader`** (line 92-94): Disables conductor and forces non-HA mode
   - Intended for disaster recovery only
   - Bypasses high-availability safety mechanisms

## Proof of Concept

```bash
# If admin API is enabled and exposed
curl -X POST http://node-ip:port \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "admin_stopSequencer",
    "params": [],
    "id": 1
  }'
```

## Exploitation Scenario
1. Attacker gains network access to the RPC endpoint (misconfiguration, internal network breach, or public exposure)
2. Attacker calls `admin_stopSequencer` to halt block production (DoS)
3. Attacker calls `admin_postUnsafePayload` with malicious payload
4. Attacker calls `admin_overrideLeader` to bypass conductor safety checks
5. Network disruption and potential chain state manipulation

## Impact
- **Denial of Service**: Ability to stop sequencer operations
- **Chain Manipulation**: Injection of unsafe payloads
- **Safety Bypass**: Disabling of conductor HA mechanisms
- **Operational Disruption**: Pipeline resets causing sync issues

## Evidence
From `/home/user/optimism/op-node/node/node.go:477-482`:
```go
if cfg.RPC.EnableAdmin {
    server.AddAPI(rpc.API{
        Namespace: "admin",
        Service:   NewAdminAPI(n.l2Driver, n.log),
    })
    n.log.Info("Admin RPC enabled")
}
```

No authentication layer is added. The admin API is directly exposed.

From `/home/user/optimism/op-node/node/api.go:79-89`:
```go
// PostUnsafePayload is a special API that allows posting an unsafe payload to the L2 derivation pipeline.
// It should only be used by op-conductor for sequencer failover scenarios.
func (n *adminAPI) PostUnsafePayload(ctx context.Context, envelope *eth.ExecutionPayloadEnvelope) error {
    payload := envelope.ExecutionPayload
    if actual, ok := envelope.CheckBlockHash(); !ok {
        log.Error("payload has bad block hash", "bad_hash", payload.BlockHash.String(), "actual", actual.String())
        return fmt.Errorf("payload has bad block hash: %s, actual block hash is: %s", payload.BlockHash.String(), actual.String())
    }

    return n.dr.OnUnsafeL2Payload(ctx, envelope)
}
```

Comment explicitly states this "should only be used by op-conductor" but there's no enforcement.

## Recommended Mitigations

### Immediate
1. **Network-level restriction**: Ensure admin RPC is ONLY bound to localhost
   - Default config should use `--rpc.admin.addr=127.0.0.1`
   - Firewall rules to block external access

2. **Deployment documentation**: Clear warnings about admin API exposure risks

### Long-term
1. **Add authentication**: Implement JWT or API key authentication for admin namespace
2. **Mutual TLS**: Require client certificates for admin API access
3. **IP allowlist**: Configuration option to restrict admin API to specific IPs
4. **Audit logging**: Log all admin API calls with source IP and timestamp
5. **Rate limiting**: Prevent brute-force attempts

## Verification Status
**VERIFIED** - Confirmed by code review:
- Admin API has no authentication mechanism in place
- Flag enables it on the configured RPC server without additional security
- Comments indicate functions are intended for restricted use but not enforced

## References
- op-node/node/api.go (admin API implementation)
- op-node/node/node.go (RPC server setup)
- op-node/flags/flags.go:484 (EnableAdmin flag default: false)

## Bug Bounty Submission Notes
- This vulnerability requires the admin API to be enabled (not default)
- However, operators may enable it for legitimate operational needs
- No defense-in-depth measures exist when enabled
- Critical impact if exploited
