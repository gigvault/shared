# 🔐 GigVault Secure Key Storage

Enterprise-grade key storage using **envelope encryption** with HSM integration.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HSM (Hardware Security Module)            │
│                                                              │
│  Master Key (NEVER leaves HSM)                              │
│    - Used to encrypt/decrypt DEKs only                      │
│    - FIPS 140-2 Level 3 certified (production)             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ↓ Encrypt/Decrypt DEKs
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                       │
│                                                              │
│  encrypted_keys table:                                      │
│    - key_id: "root-ca", "intermediate-ca-1"                │
│    - encrypted_dek: [AES-256 key encrypted by HSM]         │
│    - encrypted_key: [Private key encrypted by DEK]         │
│    - nonce: [GCM nonce]                                     │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ↓ Decrypt with DEK (in memory, briefly)
┌─────────────────────────────────────────────────────────────┐
│                    GigVault CA Service                       │
│                                                              │
│  Private Key (in memory ONLY during signing)                │
│    - Decrypted on-demand                                    │
│    - Used for signing                                       │
│    - Immediately zeroed from memory                         │
└─────────────────────────────────────────────────────────────┘
```

## 🔑 Envelope Encryption

### What is it?

**Envelope encryption** is a pattern where:
1. Data is encrypted with a **Data Encryption Key (DEK)**
2. The DEK is encrypted with a **Master Key** (in HSM)
3. Only the encrypted DEK is stored with the data

### Why use it?

✅ **Master key never leaves HSM**  
✅ **Can encrypt unlimited data** (not limited by HSM key operations)  
✅ **Fast** (bulk encryption with DEK, not HSM)  
✅ **Key rotation** is easy (re-encrypt DEKs, not all data)  
✅ **HSM vendor independent** (DEKs are standard AES)

## 📦 Usage

### 1. Initialize HSM

```go
// Development: Mock HSM
hsm, err := keystore.NewMockHSM()

// Production: Real HSM (YubiHSM, AWS CloudHSM, etc.)
hsm, err := keystore.NewYubiHSM(config)
```

### 2. Create Envelope Encryption

```go
envelope := keystore.NewEnvelopeEncryption(hsm)
```

### 3. Encrypt a Private Key

```go
// Generate or load private key
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Encrypt with envelope encryption
encryptedKey, err := envelope.EncryptPrivateKey("root-ca", privateKey)
if err != nil {
    log.Fatal(err)
}

// Store in database
storage := keystore.NewKeyStorage(db)
err = storage.Store(ctx, encryptedKey)
```

### 4. Sign Data (Key stays encrypted until needed)

```go
// Load encrypted key from database
encryptedKey, err := storage.Get(ctx, "root-ca")

// Sign data (key is decrypted, used, then immediately zeroed)
signature, err := envelope.SignWithKey(encryptedKey, dataToSign)
```

### 5. Rotate Keys (Recommended: Every 90 days)

```go
// Rotate DEK (re-encrypt with new DEK)
newEncryptedKey, err := envelope.RotateKey(encryptedKey)

// Update in database
err = storage.Store(ctx, newEncryptedKey)
```

## 🔒 Security Properties

### ✅ What This Protects Against

1. **Database compromise**: Keys are encrypted, useless without HSM
2. **Backup exposure**: Backups contain encrypted keys only
3. **Memory dumps**: Keys are in memory briefly, then zeroed
4. **Log files**: Keys never logged (only key IDs)
5. **Container images**: No keys in images

### ⚠️ What This Doesn't Protect Against

1. **Compromised HSM**: If HSM is compromised, all keys are at risk
2. **Runtime attacks**: If attacker has code execution, they can extract keys during signing
3. **Physical attacks**: Software can't protect against hardware attacks

## 🏭 Production Deployment

### Option 1: YubiHSM 2 (Recommended for on-prem)

```go
import "github.com/YubicoLabs/yubihsm-go"

hsm, err := yubihsm.NewYubiHSM(config)
```

**Pros:**
- Affordable ($650/device)
- USB-based
- FIPS 140-2 Level 3
- Tamper-proof

**Cons:**
- Single point of failure (use multiple)
- Physical access required

### Option 2: AWS CloudHSM

```go
import "github.com/aws/aws-sdk-go/service/cloudhsmv2"

hsm, err := NewAWSCloudHSM(config)
```

**Pros:**
- Cloud-managed
- High availability
- FIPS 140-2 Level 3
- Auto-backup

**Cons:**
- Expensive ($1.60/hour)
- AWS vendor lock-in

### Option 3: Azure Key Vault Premium

```go
import "github.com/Azure/azure-sdk-for-go/sdk/keyvault"

hsm, err := NewAzureKeyVault(config)
```

**Pros:**
- Cloud-managed
- HSM-backed keys
- Global availability

**Cons:**
- Expensive
- Azure vendor lock-in

## 🔄 Key Rotation Schedule

| Key Type | Rotation Period | Method |
|----------|----------------|--------|
| Master Key (HSM) | Never (or 5+ years) | Dual-control ceremony |
| DEKs | 90 days | Automated with `RotateKey()` |
| CA Private Keys | Never (re-issue cert) | Generate new CA |

## 📊 Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Encrypt key | ~5ms | One-time per key |
| Decrypt + Sign | ~10ms | Per signature operation |
| HSM decrypt DEK | ~2ms | Per key access |

## 🔍 Audit Logging

Every key operation is logged:

```sql
SELECT * FROM encrypted_keys_audit 
WHERE key_id = 'root-ca' 
ORDER BY performed_at DESC;
```

Example output:
```
key_id    | operation | performed_by       | performed_at
----------|-----------|-------------------|-------------------
root-ca   | access    | ca-service-pod-1  | 2025-10-28 15:30:00
root-ca   | rotate    | admin@gigvault.io | 2025-10-01 09:00:00
root-ca   | access    | ca-service-pod-2  | 2025-10-28 15:29:45
```

## 🚨 Incident Response

### If HSM is compromised:
1. **Immediately**: Disable HSM access
2. **Revoke**: All certificates issued by affected CAs
3. **Generate**: New master key in new HSM
4. **Re-issue**: All certificates with new CA

### If database is compromised:
1. **Verify**: HSM is not compromised
2. **Rotate**: All DEKs
3. **Audit**: Check for unauthorized key access

## 📝 Compliance

This implementation helps meet:

- ✅ **PCI DSS** - Requirement 3.4 (encryption of cardholder data)
- ✅ **HIPAA** - Encryption of ePHI
- ✅ **SOC 2** - CC6.1 (logical and physical access)
- ✅ **GDPR** - Article 32 (security of processing)
- ✅ **FIPS 140-2** - Level 3 (with hardware HSM)

## 🔗 References

- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management
- [Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption) - Google Cloud docs
- [YubiHSM 2](https://www.yubico.com/product/yubihsm-2/) - Hardware HSM
- [AWS CloudHSM](https://aws.amazon.com/cloudhsm/) - Cloud HSM

## 📄 License

Copyright © 2025 GigVault

