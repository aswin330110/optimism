# VULN-005: External VM Binary Execution with User-Controlled Inputs

## Severity
**HIGH** (potentially CRITICAL depending on input validation)

## Component
op-challenger (VM trace generation)

## Vulnerability Type
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- CWE-428: Unquoted Search Path or Element
- CWE-494: Download of Code Without Integrity Check

## Description
The op-challenger executes external VM binaries (Cannon, Asterisc) with user-controlled inputs to generate fault proofs. These binaries are invoked via `os/exec` with arguments that include data derived from on-chain game state (block numbers, state roots, preimages). If input validation is insufficient, an attacker could potentially exploit command injection, path traversal, or trigger VM binary vulnerabilities.

## Affected Code Locations
- `/home/user/optimism/op-challenger/game/fault/trace/vm/executor.go` lines 1-225
- `/home/user/optimism/op-challenger/game/fault/trace/cannon/state_converter.go` lines 1-100
- `/home/user/optimism/op-challenger/game/fault/trace/asterisc/state_converter.go` lines 1-100

## Vulnerable Code
From `/home/user/optimism/op-challenger/game/fault/trace/vm/executor.go:135-184`:

```go
func (e *Executor) DoGenerateProof(ctx context.Context, dir string, begin uint64, end uint64, extraVmArgs ...string) error {
    snapshotDir := filepath.Join(dir, SnapsDir)
    start, err := e.selectSnapshot(e.logger, snapshotDir, e.absolutePreState, begin, e.cfg.BinarySnapshots)
    if err != nil {
        return fmt.Errorf("find starting snapshot: %w", err)
    }
    proofDir := filepath.Join(dir, utils.ProofsDir)
    dataDir := PreimageDir(dir)
    lastGeneratedState := FinalStatePath(dir, e.cfg.BinarySnapshots)

    // Build command arguments - includes user-controlled data
    args := []string{
        "run",
        "--input", start,                    // File path from snapshot selection
        "--output", lastGeneratedState,      // File path
        "--meta", "",
        "--info-at", "%" + strconv.FormatUint(uint64(e.cfg.InfoFreq), 10),
        "--proof-at", "=" + strconv.FormatUint(end, 10),  // end is from on-chain data
        "--proof-fmt", filepath.Join(proofDir, "%d.json.gz"),
        "--snapshot-at", "%" + strconv.FormatUint(uint64(e.cfg.SnapshotFreq), 10),
    }

    // ... more args ...

    args = append(args, extraVmArgs...)  // EXTRA ARGS - potentially dangerous
    args = append(args, "--")

    // Oracle command arguments
    oracleArgs, err := e.oracleServer.OracleCommand(e.cfg, dataDir, e.inputs)
    if err != nil {
        return err
    }
    args = append(args, oracleArgs...)  // Oracle args from config

    // Execute the VM binary
    e.logger.Info("Generating trace", "proof", end, "cmd", e.cfg.VmBin, "args", strings.Join(args, ", "))
    execStart := time.Now()
    err = e.cmdExecutor(ctx, e.logger.New("proof", end), e.cfg.VmBin, args...)
    // ...
}
```

From `/home/user/optimism/op-challenger/game/fault/trace/cannon/state_converter.go:59-70`:

```go
func (c *CannonStateConverter) ConvertStateToProof(ctx context.Context, dir string, state uint64) ([]byte, error) {
    snapshotPath := filepath.Join(dir, vm.SnapsDir, fmt.Sprintf("%d.json.gz", state))
    proofPath := filepath.Join(dir, utils.ProofsDir, fmt.Sprintf("%d.json", state))

    args := []string{
        "witness",
        "--input", snapshotPath,
        "--output", proofPath,
    }

    cmd := exec.CommandContext(ctx, binary, args...)
    // Execute external binary
    _, err := cmd.CombinedOutput()
    // ...
}
```

## Exploitation Scenarios

### Attack Vector 1: Malicious Game Parameters
1. Attacker creates a dispute game with crafted claim values
2. Claim values influence `end` parameter or other inputs to VM
3. If proper validation missing, attacker could inject special characters
4. Example: if `end` came from untrusted source and was used in shell expansion:
   ```go
   end = "100; rm -rf /"  // Extreme example
   args = append(args, "--proof-at=" + end)
   ```
5. While `strconv.FormatUint` protects against this specific case, other inputs may not be validated

### Attack Vector 2: Path Traversal in Snapshots
1. If snapshot selection can be influenced by attacker
2. `--input` path could be manipulated via directory traversal
3. Example: `start = "../../../../etc/passwd"`
4. VM binary reads sensitive files instead of snapshot

### Attack Vector 3: Extra VM Args Injection
1. `extraVmArgs` parameter passed to `DoGenerateProof`
2. If caller doesn't properly validate these args
3. Attacker could inject additional flags:
   ```go
   extraVmArgs = []string{"--evil-flag", "--output=/tmp/backdoor"}
   ```
4. VM binary behavior altered

### Attack Vector 4: VM Binary Substitution
1. If `cfg.VmBin` path can be controlled (environment variable injection)
2. Attacker points to malicious binary:
   ```bash
   export OP_CHALLENGER_CANNON_BIN=/tmp/evil_cannon
   ```
3. Challenger executes attacker's code

### Attack Vector 5: Oracle Server Exploits
1. `oracleArgs` come from `oracleServer.OracleCommand()`
2. If oracle command generation has vulnerabilities
3. Attacker could inject malicious arguments

## Impact
- **Remote Code Execution**: If command injection successful, attacker runs arbitrary code
- **Data Exfiltration**: Path traversal could read sensitive files
- **Denial of Service**: Malicious args could crash or hang the VM binary
- **Bond Loss**: Invalid proofs generated, challenger loses bonds
- **System Compromise**: Depending on challenger's privileges, could compromise host

## Detailed Analysis

### Input Sources (Trustworthiness)
1. **On-chain game data**:
   - `end` parameter from game claims
   - Block numbers from game state
   - **Trust level**: Low - attacker controls via game creation

2. **Configuration**:
   - `cfg.VmBin`, `cfg.Server` - binary paths
   - **Trust level**: High IF properly configured, but environment variables could be injected

3. **Filesystem paths**:
   - Snapshot paths derived from state numbers
   - **Trust level**: Medium - depends on filesystem isolation

4. **Extra args**:
   - `extraVmArgs` from caller
   - **Trust level**: Depends on caller validation

### Mitigations Found in Code
1. **`strconv.FormatUint`**: Converts numbers safely, prevents injection via numeric params
2. **`filepath.Join`**: Handles path separators correctly
3. **`exec.CommandContext`**: Uses context for cancellation
4. **Separate arg array**: Not shell execution, so no shell metacharacter expansion

### Gaps in Protection
1. **No allowlist for `extraVmArgs`**: Arbitrary flags could be passed
2. **Limited path validation**: Snapshot paths not fully validated
3. **No binary verification**: VM binary integrity not checked (no signatures)
4. **No sandboxing**: VM executes with same privileges as challenger
5. **File path sanitization**: Uses `filepath.Join` but doesn't block ".." traversal attempts

## Proof of Concept

### PoC 1: Extra Args Exploitation (Conceptual)
```go
// If attacker can control extraVmArgs
maliciousArgs := []string{
    "--output=/tmp/steal_data",  // Redirect output
    "--debug-dump-memory=/tmp/memory",  // Dump memory (if such flag exists)
}

// Call DoGenerateProof with malicious args
executor.DoGenerateProof(ctx, dir, 0, 100, maliciousArgs...)
```

### PoC 2: Binary Substitution
```bash
# Create malicious binary
cat > /tmp/fake_cannon << 'EOF'
#!/bin/bash
# Steal preimage data
cp -r $PREIMAGE_DIR /tmp/stolen/
# Execute actual cannon to avoid detection
exec /real/path/to/cannon "$@"
EOF
chmod +x /tmp/fake_cannon

# Set environment variable
export OP_CHALLENGER_CANNON_BIN=/tmp/fake_cannon

# Challenger now executes malicious binary
```

## Evidence

### Direct Execution Confirmed
Line 184 in `executor.go`:
```go
err = e.cmdExecutor(ctx, e.logger.New("proof", end), e.cfg.VmBin, args...)
```

The `cmdExecutor` is typically `RunCmd`, which directly calls `exec.CommandContext`.

### Multiple Binaries Executed
- Cannon VM: `op-challenger/game/fault/trace/cannon/state_converter.go:63`
- Asterisc VM: `op-challenger/game/fault/trace/asterisc/state_converter.go:63`
- Prestate extraction: `op-challenger/game/fault/trace/vm/prestates.go:43`

### User Data Flows to Arguments
- `end` parameter (from game state) → `--proof-at` flag
- `begin` parameter → snapshot selection → `--input` flag
- `e.inputs` (game inputs) → oracle args

### No Sandboxing Found
Search for sandboxing mechanisms (seccomp, namespaces, containers) found nothing in this codebase.

## Recommended Mitigations

### Critical - Immediate
1. **Strict input validation**:
   ```go
   func validateUint64(val uint64, max uint64) error {
       if val > max {
           return fmt.Errorf("value %d exceeds max %d", val, max)
       }
       return nil
   }

   // Validate all numeric inputs
   if err := validateUint64(end, maxAllowedSteps); err != nil {
       return err
   }
   ```

2. **Path sanitization**:
   ```go
   func sanitizePath(base, path string) (string, error) {
       clean := filepath.Clean(path)
       if strings.Contains(clean, "..") {
           return "", fmt.Errorf("path traversal attempt detected")
       }
       if !filepath.IsAbs(base) {
           return "", fmt.Errorf("base must be absolute")
       }
       // Ensure path is within base directory
       fullPath := filepath.Join(base, clean)
       if !strings.HasPrefix(fullPath, base) {
           return "", fmt.Errorf("path escapes base directory")
       }
       return fullPath, nil
   }
   ```

3. **Disallow extraVmArgs** or implement strict allowlist:
   ```go
   var allowedExtraFlags = map[string]bool{
       "--verbose": true,
       "--quiet": true,
       // Strictly limited set
   }

   func validateExtraArgs(args []string) error {
       for _, arg := range args {
           if !allowedExtraFlags[arg] {
               return fmt.Errorf("disallowed flag: %s", arg)
           }
       }
       return nil
   }
   ```

4. **Binary integrity verification**:
   ```go
   func verifyBinary(path string, expectedHash string) error {
       f, err := os.Open(path)
       if err != nil {
           return err
       }
       defer f.Close()

       h := sha256.New()
       if _, err := io.Copy(h, f); err != nil {
           return err
       }

       actualHash := hex.EncodeToString(h.Sum(nil))
       if actualHash != expectedHash {
           return fmt.Errorf("binary hash mismatch")
       }
       return nil
   }
   ```

### Important - Short-term
1. **Sandboxing**: Execute VM in container or with restricted permissions
   ```go
   // Use gVisor, Firecracker, or systemd-nspawn
   cmd := exec.CommandContext(ctx, "gvisor", "run", "--", vmBin, args...)
   ```

2. **Resource limits**: Prevent resource exhaustion
   ```go
   cmd.Env = append(cmd.Env, "GOMEMLIMIT=4GiB")

   // Or use cgroups
   cmd.SysProcAttr = &syscall.SysProcAttr{
       // Set memory, CPU limits
   }
   ```

3. **Filesystem isolation**: Mount only necessary directories
   ```go
   // Use chroot or mount namespaces
   // VM should only access its data directory
   ```

### Long-term
1. **In-process VM**: Compile VM as library instead of external binary
2. **WebAssembly**: Run VM in WASM for better isolation
3. **Formal verification**: Prove VM binary behavior
4. **Deterministic build**: Ensure reproducible VM binaries
5. **Signature verification**: Sign VM binaries, verify before execution

## Real-World Risk Assessment

**Likelihood: MEDIUM-LOW**
- Requires specific attack conditions
- Input validation appears partially present (using strconv)
- However, environment variable injection or extra args could be vulnerable
- Configuration is typically controlled by operator

**Impact: HIGH**
- Successful exploitation could lead to RCE
- Challenger typically runs with significant privileges
- Could lead to complete system compromise

**Overall Risk: HIGH**

Despite medium-low likelihood, the high impact makes this a high overall risk.

## Verification Status
**PARTIALLY VERIFIED** - Code review confirms:
- External binaries ARE executed via exec.Command ✓
- Arguments include data derived from on-chain state ✓
- Some protections exist (strconv, filepath.Join) ✓
- Gaps remain (extraVmArgs, binary verification, sandboxing) ✓
- **Full exploitation requires deeper analysis** of all code paths

**Requires further testing**:
- Trace all input flows from on-chain to exec
- Fuzz test argument parsing
- Attempt path traversal exploits
- Test binary substitution scenarios

## References
- op-challenger/game/fault/trace/vm/executor.go (main execution)
- op-challenger/game/fault/trace/cannon/state_converter.go (Cannon execution)
- op-challenger/game/fault/trace/asterisc/state_converter.go (Asterisc execution)
- OWASP Command Injection guide

## Bug Bounty Submission Notes
- This finding requires **additional testing to confirm exploitability**
- Current analysis shows:
  - External execution: CONFIRMED
  - User-controlled inputs: CONFIRMED
  - Insufficient validation: PARTIAL (some validation exists)
  - Practical exploit: UNCLEAR (needs testing)
- Recommend treating as **security hardening** unless concrete exploit found
- Should implement mitigations regardless (defense in depth)

## Responsible Disclosure Notes
Given the potential for RCE, this should be disclosed responsibly:
1. Report to security team privately first
2. Allow time for patch development
3. Coordinate disclosure timeline
4. Do NOT publish exploit code until patched
