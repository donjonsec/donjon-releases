# Key Rotation Plan -- Donjon Platform Licensing

Covers the dual-signature system: ML-DSA-65 (post-quantum) + Ed25519 (classical).

**Key locations:**

| Location | What | Access |
|----------|------|--------|
| `donjonsec-infrastructure/keys/` | Canonical private + public keypairs | Local workstation, git-ignored |
| CT 100 `/opt/donjonsec-keys/` | Backup private + public keypairs | root-only, 0600 |
| `donjon-platform-clean/lib/licensing.py` | Embedded public keys (`_PUBLIC_KEY_CLASSICAL_B64`, `_PUBLIC_KEY_PQC_B64`) | Product source |
| Cloudflare KV (admin portal) | Envelope-encrypted private keys | `POST /api/keys/setup` |
| `license.donjonsec.com` | Pre-signed license blobs in KV | Read-only delivery |

---

## 1. When to Rotate

| Trigger | Urgency | Procedure |
|---------|---------|-----------|
| Key compromise (private key exposed) | IMMEDIATE | Emergency rotation (section 5) |
| Scheduled annual rotation | Planned | Full rotation (section 3) |
| Algorithm upgrade (e.g., ML-DSA-65 to ML-DSA-87) | Planned | Full rotation + code changes in signing/verification |
| Personnel change (keyholder leaves org) | Within 7 days | Full rotation |
| Signing workstation compromised | IMMEDIATE | Emergency rotation |

---

## 2. Pre-Rotation Checklist

Complete every item before generating new keys.

- [ ] **Inventory issued licenses.** Query admin portal: `GET /api/licenses` -- export full list with license IDs, customer orgs, tiers, expiry dates, and activation status.
- [ ] **Identify active vs. expired licenses.** Only active (non-expired, non-revoked) licenses need re-signing.
- [ ] **Notify customers.** Send rotation notice with:
  - Rotation date and reason (without disclosing compromise details if emergency).
  - Grace period duration (30 days standard, 7 days emergency).
  - Action required: install product update containing new public keys.
- [ ] **Back up current keys.** Copy `donjonsec-infrastructure/keys/` to a dated archive:
  ```bash
  cp -r keys/ keys-backup-$(date +%Y%m%d)/
  ```
  Also verify CT 100 backup is current:
  ```bash
  ssh root@192.168.1.100 "pct exec 100 -- ls -la /opt/donjonsec-keys/"
  ```
- [ ] **Prepare test environment.** Have a test license and a running Donjon Platform instance available for verification.

---

## 3. Rotation Procedure (Step by Step)

### 3.1 Generate New Keypair

```bash
cd C:/Users/Cris/donjonsec-infrastructure

# Archive current keys
mv keys/ keys-pre-rotation-$(date +%Y%m%d)/

# Generate new keypair
python donjon-license-admin.py keygen
```

The `keygen` command outputs base64-encoded public keys for embedding. **Save this output** -- you need both `CLASSICAL_PUBLIC_B64` and `PQC_PUBLIC_B64` values.

### 3.2 Test Signing and Verification with New Keys

```bash
# Sign a test license
python donjon-license-admin.py sign \
  --tier pro \
  --org "Rotation Test" \
  --expires 2027-12-31 \
  --output test-rotation-license.json

# Verify with the admin tool itself
python donjon-license-admin.py verify --license test-rotation-license.json
```

Do not proceed if verification fails.

### 3.3 Update Embedded Public Keys in Product

Edit `lib/licensing.py` and replace both constants with the values from `keygen` output:

```python
_PUBLIC_KEY_CLASSICAL_B64: str = "<new Ed25519 public key base64>"

_PUBLIC_KEY_PQC_B64: str = (
    "<new ML-DSA-65 public key base64 -- multiline>"
)
```

**During the grace period**, the product must accept licenses signed by EITHER the old or new keys. See section 4 for the dual-key transition implementation.

### 3.4 Update Admin Portal Keys

Upload new private keys to the admin portal for server-side signing:

1. Open `https://admin.donjonsec.com`
2. Navigate to Key Setup.
3. Upload `keys/donjon-private-classical.pem` (Ed25519) and `keys/donjon-private-pqc.bin` (ML-DSA-65).
4. Check "Force overwrite" to replace existing keys.
5. Submit -- keys are envelope-encrypted and stored in Cloudflare KV.

Or via API:
```bash
curl -X POST https://admin.donjonsec.com/api/keys/setup \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"ed25519_private_pem\": \"$(base64 -w0 keys/donjon-private-classical.pem)\",
    \"pqc_private_bin\": \"$(base64 -w0 keys/donjon-private-pqc.bin)\",
    \"force\": true
  }"
```

Verify: `GET /api/keys/status` should return configured.

### 3.5 Re-Sign All Active Licenses

For each active license in the inventory:

```bash
# For CLI-signed licenses (offline/air-gap customers):
python donjon-license-admin.py sign \
  --tier <original-tier> \
  --org "<original-org>" \
  --expires <original-expiry> \
  --fingerprint <original-fingerprint> \
  --output licenses/<license-id>.json

# For admin-portal-signed licenses:
# Use POST /api/licenses/:id/generate to re-sign server-side
```

Track re-signing progress in a spreadsheet or the admin portal's activity log.

### 3.6 Back Up New Keys to CT 100

```bash
ssh root@192.168.1.100 "pct exec 100 -- bash -c '
  mv /opt/donjonsec-keys/ /opt/donjonsec-keys-pre-rotation-\$(date +%Y%m%d)/
  mkdir -p /opt/donjonsec-keys/
'"

scp keys/donjon-private-classical.pem root@192.168.1.100:/tmp/
scp keys/donjon-private-pqc.bin root@192.168.1.100:/tmp/
scp keys/donjon-public-classical.pem root@192.168.1.100:/tmp/
scp keys/donjon-public-pqc.bin root@192.168.1.100:/tmp/

ssh root@192.168.1.100 "pct exec 100 -- bash -c '
  mv /tmp/donjon-*.pem /opt/donjonsec-keys/
  mv /tmp/donjon-*.bin /opt/donjonsec-keys/
  chmod 600 /opt/donjonsec-keys/donjon-private-*
  chmod 644 /opt/donjonsec-keys/donjon-public-*
  chown root:root /opt/donjonsec-keys/*
'"
```

### 3.7 Deploy Product Update

1. Commit the updated `lib/licensing.py` (with both old and new public keys for grace period).
2. Tag a release.
3. Distribute update to all customers.
4. For air-gapped deployments: include the re-signed license file alongside the update package.

### 3.8 Grace Period (30 Days Standard)

- Both old and new public keys are accepted during this window.
- Monitor admin portal activity log for customers still using old-key licenses.
- Send reminder notifications at day 15 and day 25.

### 3.9 Remove Old Keys

After the grace period:

1. Edit `lib/licensing.py` -- remove the old public key constants (see section 4).
2. Tag a new release.
3. Securely delete old private key archives:
   ```bash
   # Local
   shred -vfz -n 5 keys-pre-rotation-*/donjon-private-*
   rm -rf keys-pre-rotation-*/

   # CT 100
   ssh root@192.168.1.100 "pct exec 100 -- bash -c '
     shred -vfz -n 5 /opt/donjonsec-keys-pre-rotation-*/donjon-private-*
     rm -rf /opt/donjonsec-keys-pre-rotation-*/
   '"
   ```

---

## 4. Dual-Key Transition

During the grace period, `lib/licensing.py` must accept licenses signed by either the old or new keypair. Implementation approach:

### 4.1 Add Previous Key Constants

```python
# --- Current keys (active after rotation) ---
_PUBLIC_KEY_CLASSICAL_B64: str = "<new key>"
_PUBLIC_KEY_PQC_B64: str = "<new key>"

# --- Previous keys (grace period only -- remove after YYYY-MM-DD) ---
_PREV_PUBLIC_KEY_CLASSICAL_B64: str = "<old key>"
_PREV_PUBLIC_KEY_PQC_B64: str = "<old key>"
```

### 4.2 Modify Verification Logic

In `_validate_license_v2()`, attempt verification with the current keys first. If both signatures fail, retry with the previous keys:

```python
def _validate_license_v2(self, data):
    # Try current keys first
    if self._try_verify_dual(data, _PUBLIC_KEY_CLASSICAL_B64, _PUBLIC_KEY_PQC_B64):
        return True

    # Grace period: try previous keys
    if _PREV_PUBLIC_KEY_CLASSICAL_B64 and _PREV_PUBLIC_KEY_PQC_B64:
        logger.info("Current key verification failed; trying previous keys (grace period)")
        if self._try_verify_dual(data, _PREV_PUBLIC_KEY_CLASSICAL_B64, _PREV_PUBLIC_KEY_PQC_B64):
            logger.warning("License verified with PREVIOUS keys -- customer should update")
            return True

    return False
```

### 4.3 Grace Period Removal

After the grace period expires, set the previous key constants to empty strings or remove them entirely, and remove the fallback logic from `_validate_license_v2()`.

---

## 5. Emergency Rotation (Key Compromise)

Shortened procedure when a private key is known or suspected compromised.

**Timeline: Complete within 24 hours. Grace period reduced to 7 days.**

1. **Revoke the compromised keys immediately.**
   - Do NOT use the compromised keys for any further signing.
   - If admin portal keys are compromised, disable server-side signing: redeploy admin portal Worker without key bindings.

2. **Generate new keypair** (step 3.1).

3. **Identify potentially forged licenses.**
   - Any license not in the admin portal inventory is suspect.
   - Cross-reference `GET /api/licenses` with customer-reported license IDs.

4. **Re-sign and distribute all active licenses** (steps 3.2-3.5) with priority.

5. **Update all key locations** (steps 3.3, 3.4, 3.6) -- no grace period on the infrastructure side.

6. **Deploy emergency product update** with 7-day grace period for old keys.

7. **Post-incident:**
   - Document: what was compromised, how, when discovered, blast radius.
   - Notify affected customers with specifics (within 72 hours per standard practice).
   - Review access controls on key storage locations.

---

## 6. Rollback

If the rotation fails (new keys don't verify, product update breaks licensing):

### 6.1 Immediate Rollback

1. **Restore old private keys** from backup:
   ```bash
   cp -r keys-pre-rotation-YYYYMMDD/ keys/
   ```

2. **Revert `lib/licensing.py`** to the commit before key update:
   ```bash
   git revert <rotation-commit-hash>
   ```

3. **Restore admin portal keys** -- re-upload old private keys via `POST /api/keys/setup` with `force: true`.

4. **Restore CT 100 backup:**
   ```bash
   ssh root@192.168.1.100 "pct exec 100 -- bash -c '
     cp -r /opt/donjonsec-keys-pre-rotation-YYYYMMDD/ /opt/donjonsec-keys/
   '"
   ```

### 6.2 Root Cause Before Retry

Do not retry the rotation until the failure is understood and fixed. Common failure modes:

| Failure | Likely Cause | Fix |
|---------|-------------|-----|
| Verification fails on new keys | Mismatched public/private pair embedded | Re-run `keygen`, carefully copy output |
| Admin portal signing fails | Keys not properly base64-encoded or envelope encryption error | Re-upload via UI, check Worker logs |
| Customer licenses rejected | Product update not deployed before re-signed licenses | Ensure update ships first or use grace period |
| PQC signature invalid | `dilithium_py` version mismatch between admin tool and product | Pin identical versions in both environments |

---

## 7. Verification

After rotation, verify the entire chain end to end.

### 7.1 Signing Verification

```bash
cd C:/Users/Cris/donjonsec-infrastructure

# Sign a fresh license with new keys
python donjon-license-admin.py sign \
  --tier pro --org "Post-Rotation Verify" \
  --expires 2027-12-31 \
  --output verify-rotation.json

# Verify with admin tool
python donjon-license-admin.py verify --license verify-rotation.json
```

### 7.2 Product-Side Verification

```bash
cd C:/Users/Cris/donjon-platform-clean

# Start the platform and load the test license
python donjon.py --license ../donjonsec-infrastructure/verify-rotation.json

# Confirm:
# - License loads without errors
# - Tier is correctly identified as "pro"
# - All tier-gated features are accessible
# - Dashboard shows correct license metadata
```

### 7.3 Admin Portal Verification

1. `GET /api/keys/status` -- returns configured with new key fingerprints.
2. `POST /api/licenses/:id/generate` -- generate a license server-side, download it.
3. Load the server-generated license in the product -- must verify successfully.

### 7.4 Grace Period Verification (If Active)

Test that licenses signed with the OLD keys still verify during the grace period:

```bash
# Use a license signed before rotation (from backup/inventory)
python donjon.py --license old-signed-license.json
# Should verify with a warning about previous keys
```

### 7.5 Air-Gap Deployment Verification

For air-gapped customers, verify the offline flow:

1. Package the updated product with new embedded public keys.
2. Include the re-signed license file.
3. Install on an isolated machine.
4. Confirm license verification works without network access.

### 7.6 Checklist

- [ ] New keys generated and backed up to CT 100
- [ ] Test license signs and verifies with admin tool
- [ ] `lib/licensing.py` updated with new public keys (+ old keys for grace period)
- [ ] Admin portal keys updated via `/api/keys/setup`
- [ ] Server-side generated license verifies in product
- [ ] All active licenses re-signed
- [ ] Product update deployed/distributed
- [ ] Air-gap package updated
- [ ] Old-key licenses verify during grace period
- [ ] Grace period expiry date documented and calendar reminder set
- [ ] Old keys removed after grace period
