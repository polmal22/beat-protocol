# BEAT TECHNICAL SPECIFICATION v1.1

**Complete Technical Documentation**

*Updated: February 15, 2026*  
*Status: Concept Phase*  
*License: MIT*

---

## Table of Contents

1. [Overview](#1-overview)
2. [Core Philosophy: Attack Economics](#2-core-philosophy-attack-economics)
3. [Cryptographic Foundation](#3-cryptographic-foundation)
4. [Data Structures](#4-data-structures)
5. [Network Architecture](#5-network-architecture)
6. [Mobile Mint (Primary Model)](#6-mobile-mint-primary-model)
7. [Full Mint (Optional Backbone)](#7-full-mint-optional-backbone)
8. [Transfer Protocols](#8-transfer-protocols)
9. [Sybil Resistance Through Friction](#9-sybil-resistance-through-friction)
10. [Security Model](#10-security-model)
11. [Database Schemas](#11-database-schemas)
12. [API Specifications](#12-api-specifications)
13. [Deployment Guide](#13-deployment-guide)
14. [Testing Strategy](#14-testing-strategy)
15. [Performance Targets](#15-performance-targets)
16. [Future Enhancements](#16-future-enhancements)

---

## 1. Overview

### 1.1 Fundamental Architecture

Beat Protocol is a decentralized social exchange system where **every smartphone automatically operates as a network validator (mint)**. This is not an optional feature—it is the core architecture.
```
┌─────────────────────────────────────────────┐
│  Every smartphone = Mint                     │
│  (This is the default, not optional)        │
└─────────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
    ┌───▼────┐            ┌────▼────┐
    │ Mobile │            │  Full   │
    │  Mint  │            │  Mint   │
    │        │            │         │
    │  95%   │            │   5%    │
    │network │            │backbone │
    └────────┘            └─────────┘

Every user               Enthusiasts
Automatic                Optional
Resource-conscious       24/7 helping
```

### 1.2 Technology Stack

**Mobile Client:**
- Android: Kotlin + Jetpack Compose
- iOS: Swift + SwiftUI
- Biometrics: Android Keystore / iOS Secure Enclave
- Storage: SQLCipher (encrypted SQLite)
- Network: libp2p (WebSocket transport)

**Full Mint Server:**
- Runtime: Node.js 18+ OR Go 1.21+ OR Rust 1.75+
- Database: PostgreSQL 15+ OR SQLite (small deployments)
- Network: libp2p (TCP + WebSocket)
- Crypto: libsodium / OpenSSL

**Cryptography:**
- Signatures: Ed25519
- Key derivation: Argon2id
- Hashing: BLAKE3
- ZK Proofs: Bulletproofs OR Groth16
- Encryption: ChaCha20-Poly1305

### 1.3 Key Insight: Beat as UBI First
```
Traditional thinking:
  Money = store of value → protect from inflation → prevent fake accounts

Beat thinking:
  Money = UBI tool → ensure circulation → make attacks economically pointless

This changes EVERYTHING about security design.
```

---

## 2. Core Philosophy: Attack Economics

### 2.1 Attack is NOT Theft, It's Dilution
```
What an attacker actually does:

❌ NOT: "Steal money from others"
✅ YES: "Add fake people to dilute the pool"

Example:
  Community: 100 real people
  Attack: 20 fake accounts added
  
  Before attack:
    Each person: 10 BEAT/day
    Total emission: 1,000 BEAT/day
    
  After attack:
    Each person: still 10 BEAT/day
    Total emission: 1,200 BEAT/day
    
  Effect: 20% dilution
  
This is inflation, not theft.
Very different threat model.
```

### 2.2 Why Attacks Become Pointless
```
Traditional money:
  1. Steal
  2. Disappear
  3. Enjoy wealth
  ✓ Attack succeeds

Beat:
  1. Create fake accounts
  2. Generate BEAT daily
  3. Must maintain activity (or detected)
  4. Must spend quickly (demurrage)
  5. Must find real value exchange
  6. Can't disappear (ongoing operation)
  ✗ Attack is exhausting

The system has GRAVITATIONAL PULL:
  - Can't hoard (demurrage)
  - Can't cash out (no fiat conversion)
  - Can't stop (tokens expire)
  - Must interact (or lose reputation)
```

### 2.3 Real Attack Economics
```javascript
// Cost-benefit analysis for attacker

const ATTACK_SCENARIO = {
  fakeAccounts: 20,
  realPeople: 100,
  
  // Costs
  costs: {
    devices: 20 * 100, // $100 per used phone = $2,000
    biometricBypass: 20 * 50, // $50 per fake = $1,000
    vouchers: 60 * 10, // Need 60 vouchers (3 each) = $600
    maintenance: 20 * 5, // $5/month per account = $100/month
    timeInvestment: 'Enormous (daily management)',
    riskOfDetection: 'High (graph analysis)',
    reputationLoss: 'Total (if caught)'
  },
  
  // Benefits
  benefits: {
    dailyIncome: 20 * 10, // 200 BEAT/day
    BUT: {
      gradualActivation: '20 accounts × 10 months = wait',
      demurrage: '-5% to -15% monthly on excess',
      noLiquidity: 'Where to spend 200 BEAT/day?',
      localInflation: 'Prices adjust (others notice)',
      detection: 'Graph analysis will flag cluster'
    }
  },
  
  // Reality check
  realGain: {
    month1: 20 * 1 * 30, // 600 BEAT (only 1/day at start)
    month6: 20 * 6 * 30, // 3,600 BEAT (ramping up)
    month12: 20 * 10 * 30, // 6,000 BEAT (full rate)
    
    butWithDemurrage: {
      month1: 600, // Under fireproof base, safe
      month6: 3600 - (1600 * 0.05), // Losing ~80/month
      month12: 6000 - (1000 * 0.05 + 5000 * 0.15) // Losing ~800/month
    },
    
    netAfterYear: '~5,000 BEAT per fake account',
    totalNet: '100,000 BEAT for 20 fakes',
    
    worthIt: 'NO if:',
    reasons: [
      'Spent $3,700 + ongoing time',
      'Risk of detection and blacklist',
      'Local market can only absorb so much',
      'Constant maintenance required',
      'No exit strategy (can\'t cash out)'
    ]
  }
};

// Conclusion: Attack is possible but economically stupid
```

### 2.4 What Happens IF Attack Succeeds?
```
Scenario: 100 real people + 20 undetected fakes

Immediate effect:
  - Total emission: 1,000 → 1,200 BEAT/day (+20%)
  - No individual loses BEAT
  - But: 20% more BEAT chasing same goods
  
Local market response:
  Week 1: Prices stable (people don't notice)
  Week 2: Some sellers notice "more buyers"
  Week 3: Prices start adjusting
  Week 4: Coffee was 5 BEAT → now 6 BEAT
  
  New equilibrium:
    Prices rise ~20%
    Real people still get 10 BEAT/day
    Purchasing power slightly reduced
    BUT: fireproof base (5,000) still protected
    
System self-corrects through price discovery.
This is acceptable damage.

Compare to Bitcoin:
  If attacker creates 20% fake coins → catastrophic
  
In Beat:
  If attacker creates 20% fake people → mild inflation
  
Why? Because value = real goods/services, not token scarcity
```

---

## 3. Cryptographic Foundation

### 3.1 Key Generation

#### Master Seed
```typescript
// User's master secret (from seed phrase)
const SEED_PHRASE_WORDS = 12; // BIP39 compatible

function generateMasterSeed(): {
  seedPhrase: string[],
  masterSeed: Uint8Array
} {
  // Generate 128 bits of entropy
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  
  // Convert to BIP39 mnemonic
  const seedPhrase = bip39.entropyToMnemonic(entropy);
  
  // Derive master seed (512 bits)
  const masterSeed = bip39.mnemonicToSeed(seedPhrase);
  
  return { seedPhrase: seedPhrase.split(' '), masterSeed };
}
```

#### Key Derivation Hierarchy
```
Master Seed (512 bits)
    │
    ├─► Identity Key (Ed25519)
    │   └─► Used for: ZK commitments, mint registration
    │
    ├─► Signing Key (Ed25519)  
    │   └─► Used for: Token signatures, transaction auth
    │
    └─► Encryption Key (X25519)
        └─► Used for: P2P messages, backup encryption
```
```typescript
// BIP32-like derivation
function deriveKeys(masterSeed: Uint8Array): {
  identityKey: KeyPair,
  signingKey: KeyPair,
  encryptionKey: KeyPair
} {
  // Derive identity key (path: m/44'/0'/0'/0)
  const identityKey = ed25519.keyFromSeed(
    hkdf(masterSeed, 'beat-identity', 32)
  );
  
  // Derive signing key (path: m/44'/0'/0'/1)
  const signingKey = ed25519.keyFromSeed(
    hkdf(masterSeed, 'beat-signing', 32)
  );
  
  // Derive encryption key (path: m/44'/0'/0'/2)
  const encryptionKey = x25519.keyFromSeed(
    hkdf(masterSeed, 'beat-encryption', 32)
  );
  
  return { identityKey, signingKey, encryptionKey };
}

// HKDF for key derivation
function hkdf(
  ikm: Uint8Array,     // Input key material
  info: string,        // Context string
  length: number       // Output length in bytes
): Uint8Array {
  // Extract
  const prk = hmacSha256(new Uint8Array(32), ikm);
  
  // Expand
  const okm = new Uint8Array(length);
  const infoBytes = new TextEncoder().encode(info);
  
  let prev = new Uint8Array(0);
  let counter = 1;
  let offset = 0;
  
  while (offset < length) {
    const input = new Uint8Array(prev.length + infoBytes.length + 1);
    input.set(prev);
    input.set(infoBytes, prev.length);
    input[prev.length + infoBytes.length] = counter;
    
    prev = hmacSha256(prk, input);
    
    const copyLength = Math.min(prev.length, length - offset);
    okm.set(prev.subarray(0, copyLength), offset);
    
    offset += copyLength;
    counter++;
  }
  
  return okm;
}
```

---

### 3.2 Biometric Protection

#### Local Storage (Never Leaves Device)
```typescript
interface BiometricData {
  fingerprintTemplate: Uint8Array;  // Raw biometric data
  deviceSecret: Uint8Array;         // 256-bit random (unique per device)
  salt: Uint8Array;                 // 128-bit random
}

// Hash fingerprint with Argon2id
async function hashBiometric(data: BiometricData): Promise<Uint8Array> {
  const params = {
    timeCost: 3,        // Iterations
    memoryCost: 65536,  // 64 MB
    parallelism: 4,     // Threads
    hashLength: 32      // Output size
  };
  
  // Combine fingerprint + device secret
  const input = new Uint8Array(
    data.fingerprintTemplate.length + data.deviceSecret.length
  );
  input.set(data.fingerprintTemplate);
  input.set(data.deviceSecret, data.fingerprintTemplate.length);
  
  // Hash with Argon2id
  const hash = await argon2.hash({
    pass: input,
    salt: data.salt,
    ...params
  });
  
  // Store in Secure Element
  await secureStorage.store('biometric_hash', hash);
  
  return hash;
}
```

#### Android Implementation
```kotlin
// Android Keystore + BiometricPrompt
class BiometricManager(private val context: Context) {
    
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    
    // Generate key in Secure Enclave
    fun generateBiometricKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        
        val builder = KeyGenParameterSpec.Builder(
            "beat_biometric_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(30)
            .setInvalidatedByBiometricEnrollment(true)
        
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }
    
    // Authenticate and get hash
    suspend fun authenticateAndHash(): Result<ByteArray> = suspendCoroutine { cont ->
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Beat Authentication")
            .setSubtitle("Confirm fingerprint to generate daily BEAT")
            .setNegativeButtonText("Cancel")
            .build()
        
        val biometricPrompt = BiometricPrompt(
            context as FragmentActivity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    // Extract fingerprint template
                    val template = extractTemplate(result)
                    
                    // Hash with Argon2
                    val hash = hashBiometric(template)
                    
                    cont.resume(Result.success(hash))
                }
                
                override fun onAuthenticationFailed() {
                    cont.resume(Result.failure(Exception("Auth failed")))
                }
            }
        )
        
        biometricPrompt.authenticate(promptInfo)
    }
}
```

#### iOS Implementation
```swift
// iOS Secure Enclave + LocalAuthentication
import LocalAuthentication
import CryptoKit

class BiometricManager {
    
    // Generate key in Secure Enclave
    func generateBiometricKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        )!
        
        return try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: accessControl
        )
    }
    
    // Authenticate and get hash
    func authenticateAndHash() async throws -> Data {
        let context = LAContext()
        
        // Check biometry available
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw error ?? NSError(domain: "BiometricManager", code: -1)
        }
        
        // Authenticate
        let reason = "Confirm fingerprint to generate daily BEAT"
        let success = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
        
        guard success else {
            throw NSError(domain: "BiometricManager", code: -2)
        }
        
        // Extract template
        let template = try extractTemplate(from: context)
        
        // Hash with Argon2
        let hash = try hashBiometric(template)
        
        return hash
    }
    
    private func hashBiometric(_ template: Data) throws -> Data {
        let deviceSecret = try loadOrGenerateDeviceSecret()
        let salt = try loadOrGenerateSalt()
        
        let input = template + deviceSecret
        
        // Call Argon2 (via C bridge or Swift package)
        let hash = Argon2.hash(
            password: input,
            salt: salt,
            iterations: 3,
            memoryKB: 65536,
            parallelism: 4,
            hashLength: 32
        )
        
        // Store in Keychain
        try Keychain.store(hash, key: "biometric_hash")
        
        return hash
    }
}
```

---

### 3.3 Zero-Knowledge Proofs

#### Commitment Scheme
```typescript
// Generate ZK commitment from biometric hash
function generateCommitment(biometricHash: Uint8Array): {
  commitment: Uint8Array,
  blinding: Uint8Array
} {
  // Random blinding factor
  const blinding = crypto.getRandomValues(new Uint8Array(32));
  
  // Pedersen commitment: C = H(hash || blinding)
  const commitment = blake3.hash(
    concat(biometricHash, blinding)
  );
  
  return { commitment, blinding };
}

// Store commitment on network (public)
// Store blinding locally (secret)
```

#### Proof Generation (Bulletproofs)
```typescript
// Prove uniqueness without revealing hash
async function generateUniquenessProof(
  biometricHash: Uint8Array,
  blinding: Uint8Array,
  existingCommitments: Uint8Array[]
): Promise<Proof> {
  
  // Statement: "I have a unique hash not in existingCommitments"
  const statement = {
    type: 'set_non_membership',
    commitment: blake3.hash(concat(biometricHash, blinding)),
    set: existingCommitments
  };
  
  // Witness (private inputs)
  const witness = {
    value: biometricHash,
    blinding: blinding
  };
  
  // Generate proof with Bulletproofs
  const proof = await bulletproofs.prove({
    statement,
    witness,
    curve: 'secp256k1'
  });
  
  return proof;
}

// Verify proof (anyone can do this)
async function verifyUniquenessProof(
  commitment: Uint8Array,
  proof: Proof,
  existingCommitments: Uint8Array[]
): Promise<boolean> {
  
  const statement = {
    type: 'set_non_membership',
    commitment: commitment,
    set: existingCommitments
  };
  
  return await bulletproofs.verify({
    statement,
    proof,
    curve: 'secp256k1'
  });
}
```

#### Daily Token Generation
```typescript
// Generate new token each day (prevents tracking)
function generateDailyToken(
  identityKey: KeyPair,
  date: Date
): {
  token: Uint8Array,
  signature: Uint8Array
} {
  // Deterministic but changes daily
  const dateString = date.toISOString().split('T')[0]; // YYYY-MM-DD
  
  // Token = HMAC(identityKey, date)
  const token = hmacSha256(
    identityKey.secretKey,
    new TextEncoder().encode(dateString)
  );
  
  // Sign token
  const signature = ed25519.sign(token, identityKey.secretKey);
  
  return { token, signature };
}
```

#### Why ZK Proofs Matter in Context of Attacks
```
ZK Proofs don't make attacks impossible.
They make attacks:
  1. More expensive (bypass costs)
  2. More detectable (anomalies visible)
  3. More risky (evidence trail)
  
This increases cost/benefit ratio against attacker.
```

---

## 4. Data Structures

### 4.1 Token Structure
```typescript
interface BeatToken {
  // Metadata
  version: number;           // Protocol version (currently 1)
  serial: string;            // Unique ID (UUID v4)
  value: number;             // Amount in BEAT (integer, no decimals)
  
  // Ownership chain
  issuer: Uint8Array;        // Public key of original issuer (identity key)
  currentOwner: Uint8Array;  // Public key of current owner
  ownershipChain: Signature[]; // History of transfers
  
  // Timestamps
  issuedAt: number;          // Unix timestamp (seconds)
  expiresAt: number;         // Optional: for short-lived tokens
  
  // Demurrage tracking (optional)
  lastDemurrageApplied?: number; // Unix timestamp
  
  // Signature
  signature: Uint8Array;     // Ed25519 signature of entire token
}

interface Signature {
  publicKey: Uint8Array;     // Signer's public key
  timestamp: number;         // When signed
  signature: Uint8Array;     // Ed25519 signature
}

// Serialization (for storage and transfer)
function serializeToken(token: BeatToken): Uint8Array {
  // Use MessagePack for compact binary format
  return msgpack.encode(token);
}

function deserializeToken(data: Uint8Array): BeatToken {
  return msgpack.decode(data);
}

// Signing
function signToken(token: BeatToken, secretKey: Uint8Array): BeatToken {
  // Serialize without signature
  const { signature, ...unsignedToken } = token;
  const data = msgpack.encode(unsignedToken);
  
  // Sign
  const sig = ed25519.sign(data, secretKey);
  
  // Add signature
  return { ...token, signature: sig };
}

// Verification
function verifyToken(token: BeatToken): boolean {
  // Check signature
  const { signature, ...unsignedToken } = token;
  const data = msgpack.encode(unsignedToken);
  
  if (!ed25519.verify(data, signature, token.currentOwner)) {
    return false;
  }
  
  // Verify ownership chain
  for (let i = 0; i < token.ownershipChain.length; i++) {
    const sig = token.ownershipChain[i];
    
    // Each transfer must be signed by previous owner
    const prevOwner = i === 0 ? token.issuer : token.ownershipChain[i - 1].publicKey;
    
    const transferData = msgpack.encode({
      serial: token.serial,
      from: prevOwner,
      to: sig.publicKey,
      timestamp: sig.timestamp
    });
    
    if (!ed25519.verify(transferData, sig.signature, prevOwner)) {
      return false;
    }
  }
  
  return true;
}
```

### 4.2 Transaction Structure
```typescript
interface Transaction {
  // Transaction ID
  txid: string;              // BLAKE3 hash of transaction
  
  // Participants
  sender: Uint8Array;        // Public key
  receiver: Uint8Array;      // Public key
  
  // Amount
  amount: number;            // BEAT amount (integer)
  
  // Tokens being transferred
  tokens: BeatToken[];       // Array of tokens (sum = amount)
  
  // Metadata
  timestamp: number;         // Unix timestamp
  memo?: string;             // Optional note (max 256 bytes)
  
  // Transfer type
  type: 'nfc' | 'qr' | 'online';
  
  // For online transfers only
  mintValidation?: {
    mintId: string;          // Which mint validated
    blockHeight: number;     // At what checkpoint
    proof: Uint8Array;       // Merkle proof of inclusion
  };
  
  // Signatures
  senderSignature: Uint8Array;
  receiverSignature?: Uint8Array; // Optional: for escrow
}

// Create transaction
function createTransaction(
  tokens: BeatToken[],
  receiver: Uint8Array,
  senderKey: KeyPair,
  memo?: string
): Transaction {
  const tx: Transaction = {
    txid: '', // Will be calculated
    sender: senderKey.publicKey,
    receiver: receiver,
    amount: tokens.reduce((sum, t) => sum + t.value, 0),
    tokens: tokens,
    timestamp: Date.now(),
    memo: memo,
    type: 'nfc', // Default
    senderSignature: new Uint8Array(64)
  };
  
  // Sign
  const data = msgpack.encode({
    sender: tx.sender,
    receiver: tx.receiver,
    amount: tx.amount,
    tokens: tx.tokens.map(t => t.serial),
    timestamp: tx.timestamp,
    memo: tx.memo
  });
  
  tx.senderSignature = ed25519.sign(data, senderKey.secretKey);
  
  // Calculate txid
  tx.txid = blake3.hash(msgpack.encode(tx)).toString('hex');
  
  return tx;
}
```

### 4.3 Fraud Proof
```typescript
interface FraudProof {
  // Type of fraud
  type: 'double_spend' | 'fake_identity' | 'invalid_signature';
  
  // Fraudster
  publicKey: Uint8Array;
  
  // Evidence
  evidence: {
    // For double-spend
    transaction1?: Transaction;
    transaction2?: Transaction;
    sameSerial: string;
    
    // For fake identity
    duplicateCommitment?: Uint8Array;
    
    // For invalid signature
    invalidTransaction?: Transaction;
  };
  
  // Discoverer
  reportedBy: string;        // Mint ID
  reportedAt: number;        // Unix timestamp
  
  // Proof signature
  signature: Uint8Array;     // Signed by reporting mint
}

// Create fraud proof for double-spend
function createDoubleSpendProof(
  tx1: Transaction,
  tx2: Transaction,
  mintKey: KeyPair
): FraudProof {
  // Find common serial
  const serials1 = new Set(tx1.tokens.map(t => t.serial));
  const commonSerial = tx2.tokens.find(t => serials1.has(t.serial))!.serial;
  
  const proof: FraudProof = {
    type: 'double_spend',
    publicKey: tx1.sender, // Fraudster
    evidence: {
      transaction1: tx1,
      transaction2: tx2,
      sameSerial: commonSerial
    },
    reportedBy: mintKey.publicKey.toString('hex'),
    reportedAt: Date.now(),
    signature: new Uint8Array(64)
  };
  
  // Sign proof
  const data = msgpack.encode({
    type: proof.type,
    publicKey: proof.publicKey,
    evidence: proof.evidence,
    reportedBy: proof.reportedBy,
    reportedAt: proof.reportedAt
  });
  
  proof.signature = ed25519.sign(data, mintKey.secretKey);
  
  return proof;
}

// Verify fraud proof
function verifyFraudProof(proof: FraudProof): boolean {
  // Verify signature
  const { signature, ...unsignedProof } = proof;
  const data = msgpack.encode(unsignedProof);
  
  // Get reporting mint's public key (from network)
  const mintKey = getMintPublicKey(proof.reportedBy);
  
  if (!ed25519.verify(data, signature, mintKey)) {
    return false;
  }
  
  // Verify evidence
  if (proof.type === 'double_spend') {
    const { transaction1, transaction2, sameSerial } = proof.evidence;
    
    // Both transactions must be valid
    if (!verifyTransaction(transaction1) || !verifyTransaction(transaction2)) {
      return false;
    }
    
    // Both must use same serial
    const serials1 = transaction1.tokens.map(t => t.serial);
    const serials2 = transaction2.tokens.map(t => t.serial);
    
    if (!serials1.includes(sameSerial) || !serials2.includes(sameSerial)) {
      return false;
    }
    
    // Both must be from same sender
    if (!arrayEquals(transaction1.sender, transaction2.sender)) {
      return false;
    }
    
    return true;
  }
  
  return false;
}
```

---

## 5. Network Architecture

### 5.1 Revised Topology: Mobile-First
```
┌──────────────────────────────────────────────┐
│  95% of network = Smartphones (Mobile Mints) │
│  5% of network = Always-on (Full Mints)      │
└──────────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼────┐            ┌────▼────┐
    │ Europe  │            │  Asia   │
    │ Region  │            │ Region  │
    └────┬────┘            └────┬────┘
         │                       │
    ┌────▼────┐            ┌────▼────┐
    │ Berlin  │            │Bangkok  │
    │  City   │            │  City   │
    └────┬────┘            └────┬────┘
         │                       │
         │  Most users HERE      │
         │  (mobile mints)       │
         │                       │
    ┌────▼──────────────┐  ┌────▼─────────────┐
    │ 500 smartphones   │  │ 300 smartphones  │
    │ (intermittent)    │  │ (intermittent)   │
    │                   │  │                  │
    │ + 5 full nodes    │  │ + 3 full nodes   │
    │   (backbone)      │  │   (backbone)     │
    └───────────────────┘  └──────────────────┘
```

### 5.2 libp2p Configuration

#### Mobile Mint Configuration
```typescript
import { createLibp2p } from 'libp2p';
import { webSockets } from '@libp2p/websockets';
import { noise } from '@chainsafe/libp2p-noise';
import { mplex } from '@libp2p/mplex';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { kadDHT } from '@libp2p/kad-dht';
import { bootstrap } from '@libp2p/bootstrap';

// Mobile mint configuration
async function createMobileMintNode() {
  const node = await createLibp2p({
    addresses: {
      listen: [
        // Only WebSocket (works through WiFi)
        '/ip4/0.0.0.0/tcp/0/ws'
      ]
    },
    transports: [webSockets()],
    connectionEncryption: [noise()],
    streamMuxers: [mplex()],
    
    // Gossip with battery optimization
    pubsub: gossipsub({
      emitSelf: false,
      globalSignaturePolicy: 'StrictSign',
      
      // Mobile optimizations
      heartbeatInterval: 60000, // 1 min (vs 1 sec default)
      fanoutTTL: 30000, // 30 sec
      mcacheLength: 5, // Small cache
      mcacheGossip: 3
    }),
    
    // DHT in client mode (don't store data)
    dht: kadDHT({
      clientMode: true, // Mobile = client only
      kBucketSize: 10 // Small routing table
    }),
    
    // Connection limits (battery-conscious)
    connectionManager: {
      maxConnections: 10, // Max 10 peers
      minConnections: 3,  // Min 3 peers
      pollInterval: 60000 // Check every minute
    },
    
    peerDiscovery: [
      // Bootstrap from full nodes
      bootstrap({
        list: [
          '/dns4/boot1.beat-protocol.org/tcp/9000/ws/p2p/12D3KooW...',
          '/dns4/boot2.beat-protocol.org/tcp/9000/ws/p2p/12D3KooW...'
        ],
        timeout: 10000
      })
    ]
  });
  
  await node.start();
  return node;
}
```

#### Full Mint Configuration
```typescript
import { tcp } from '@libp2p/tcp';
import { mdns } from '@libp2p/mdns';

// Full mint configuration
async function createFullMintNode() {
  const node = await createLibp2p({
    addresses: {
      listen: [
        '/ip4/0.0.0.0/tcp/9000', // TCP for other full nodes
        '/ip4/0.0.0.0/tcp/9001/ws' // WebSocket for mobile nodes
      ]
    },
    transports: [tcp(), webSockets()],
    connectionEncryption: [noise()],
    streamMuxers: [mplex()],
    
    pubsub: gossipsub({
      emitSelf: false,
      globalSignaturePolicy: 'StrictSign',
      // Default intervals (more aggressive)
    }),
    
    // DHT in server mode (store routing data)
    dht: kadDHT({
      clientMode: false,
      kBucketSize: 20
    }),
    
    connectionManager: {
      maxConnections: 100,
      minConnections: 10
    },
    
    peerDiscovery: [
      bootstrap({
        list: [/* ... */]
      }),
      mdns() // Local discovery
    ]
  });
  
  await node.start();
  return node;
}
```

### 5.3 Gossip Protocol
```typescript
// Topics
const TOPICS = {
  TRANSACTIONS: '/beat/transactions/1.0.0',
  FRAUD_PROOFS: '/beat/fraud/1.0.0',
  CHECKPOINTS: '/beat/checkpoints/1.0.0',
  ANNOUNCEMENTS: '/beat/announcements/1.0.0'
};

// Subscribe to transaction gossip
node.pubsub.subscribe(TOPICS.TRANSACTIONS);

node.pubsub.addEventListener('message', async (event) => {
  if (event.detail.topic === TOPICS.TRANSACTIONS) {
    const tx = msgpack.decode(event.detail.data);
    
    // Validate transaction
    if (await validateTransaction(tx)) {
      // Check for double-spend
      const isDoubleSpend = await checkDoubleSpend(tx);
      
      if (isDoubleSpend) {
        // Create and broadcast fraud proof
        const proof = createFraudProof(tx);
        await node.pubsub.publish(
          TOPICS.FRAUD_PROOFS,
          msgpack.encode(proof)
        );
      } else {
        // Store transaction
        await storeTransaction(tx);
        
        // Re-broadcast to neighbors
        await node.pubsub.publish(
          TOPICS.TRANSACTIONS,
          event.detail.data
        );
      }
    }
  }
});

// Publish new transaction
async function broadcastTransaction(tx: Transaction) {
  const data = msgpack.encode(tx);
  await node.pubsub.publish(TOPICS.TRANSACTIONS, data);
}
```

---

## 6. Mobile Mint (Primary Model)

### 6.1 Core Principle
```
Every Beat user automatically runs a mint.
This is NOT optional.
This is the default.

Why this matters:
  - True decentralization (no reliance on volunteers)
  - Network scales with users (more users = more mints)
  - No "mining" inequality (everyone participates equally)
  - Resilient (lose 50% of mints = network still works)
```

### 6.2 Background Service Implementation

#### Android
```kotlin
class BeatMintService : Service() {
    
    private lateinit var mint: MobileMint
    private val batteryManager by lazy { 
        getSystemService(Context.BATTERY_SERVICE) as BatteryManager 
    }
    
    override fun onCreate() {
        super.onCreate()
        
        mint = MobileMint(
            wallet = walletManager,
            context = this
        )
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Required: show notification (Android foreground service)
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
        
        // Start mint with smart conditions
        lifecycleScope.launch {
            mint.startConditional()
        }
        
        // Monitor conditions
        registerConditionalListeners()
        
        return START_STICKY // Restart if killed
    }
    
    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Beat Network")
            .setContentText("Helping validate transactions")
            .setSmallIcon(R.drawable.ic_beat_small)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN) // Minimal annoyance
            .build()
    }
    
    private fun registerConditionalListeners() {
        // Battery level
        val batteryFilter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
                val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
                val percentage = level / scale.toFloat()
                val isCharging = intent.getIntExtra(
                    BatteryManager.EXTRA_STATUS, -1
                ) == BatteryManager.BATTERY_STATUS_CHARGING
                
                lifecycleScope.launch {
                    mint.onBatteryChanged(percentage, isCharging)
                }
            }
        }, batteryFilter)
        
        // Network type
        val connectivityFilter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val network = cm.activeNetwork
                val capabilities = cm.getNetworkCapabilities(network)
                
                val isWiFi = capabilities?.hasTransport(
                    NetworkCapabilities.TRANSPORT_WIFI
                ) ?: false
                
                lifecycleScope.launch {
                    mint.onNetworkChanged(isWiFi)
                }
            }
        }, connectivityFilter)
        
        // Screen state
        val screenFilter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val screenOn = intent.action == Intent.ACTION_SCREEN_ON
                
                lifecycleScope.launch {
                    mint.onScreenStateChanged(screenOn)
                }
            }
        }, screenFilter)
    }
}

class MobileMint(
    private val wallet: WalletManager,
    private val context: Context
) {
    private var currentMode = MintMode.STOPPED
    private var p2pNode: Libp2p? = null
    private val db = MintDatabase(context)
    
    suspend fun startConditional() {
        // Determine appropriate mode
        val mode = determineMode()
        
        if (mode == MintMode.STOPPED) {
            Log.d("MobileMint", "Conditions not met, staying dormant")
            return
        }
        
        currentMode = mode
        
        // Start P2P node
        p2pNode = createMobileMintNode()
        
        // Connect to peers
        connectToNearbyPeers()
        
        // Subscribe to relevant topics
        subscribeToTopics()
        
        // Start validation loop
        startValidationLoop()
        
        Log.d("MobileMint", "Started in mode: $mode")
    }
    
    private fun determineMode(): MintMode {
        val battery = getBatteryLevel()
        val isCharging = isCharging()
        val isWiFi = isConnectedToWiFi()
        val screenOn = isScreenOn()
        
        return when {
            // Critical battery - stop completely
            battery < 0.2f -> MintMode.STOPPED
            
            // Optimal conditions - aggressive mode
            isCharging && isWiFi && !screenOn -> MintMode.AGGRESSIVE
            
            // Good conditions - normal mode
            battery > 0.5f && isWiFi && !screenOn -> MintMode.NORMAL
            
            // Poor conditions - minimal mode
            battery > 0.3f && isWiFi -> MintMode.MINIMAL
            
            // Bad conditions - stop
            else -> MintMode.STOPPED
        }
    }
    
    suspend fun onBatteryChanged(level: Float, charging: Boolean) {
        val newMode = determineMode()
        
        if (newMode != currentMode) {
            Log.d("MobileMint", "Mode change: $currentMode -> $newMode")
            
            when (newMode) {
                MintMode.STOPPED -> stop()
                MintMode.MINIMAL -> switchToMinimal()
                MintMode.NORMAL -> switchToNormal()
                MintMode.AGGRESSIVE -> switchToAggressive()
            }
            
            currentMode = newMode
        }
    }
    
    suspend fun onNetworkChanged(isWiFi: Boolean) {
        if (!isWiFi && currentMode != MintMode.STOPPED) {
            // Lost WiFi - pause immediately
            Log.d("MobileMint", "Lost WiFi, pausing")
            pause()
        } else if (isWiFi && currentMode == MintMode.STOPPED) {
            // Got WiFi - resume if battery allows
            Log.d("MobileMint", "Got WiFi, checking if can resume")
            startConditional()
        }
    }
    
    private suspend fun startValidationLoop() {
        while (currentMode != MintMode.STOPPED) {
            // Get validation interval based on mode
            val interval = when (currentMode) {
                MintMode.AGGRESSIVE -> 5_000L // 5 seconds
                MintMode.NORMAL -> 30_000L // 30 seconds
                MintMode.MINIMAL -> 120_000L // 2 minutes
                MintMode.STOPPED -> break
            }
            
            // Validate pending transactions
            try {
                val pending = db.getPendingTransactions()
                for (tx in pending) {
                    if (shouldValidate(tx)) {
                        validateTransaction(tx)
                    }
                }
            } catch (e: Exception) {
                Log.e("MobileMint", "Validation error", e)
            }
            
            delay(interval)
        }
    }
    
    private fun shouldValidate(tx: Transaction): Boolean {
        // Priority 1: My own transactions (always)
        if (wallet.isMyKey(tx.sender) || wallet.isMyKey(tx.receiver)) {
            return true
        }
        
        // Priority 2: My contacts
        if (wallet.isContact(tx.sender) || wallet.isContact(tx.receiver)) {
            return true
        }
        
        // Priority 3: Local region
        if (isLocalTransaction(tx) && currentMode == MintMode.AGGRESSIVE) {
            return true
        }
        
        // Priority 4: Random sampling (only in aggressive mode)
        if (currentMode == MintMode.AGGRESSIVE && Random.nextFloat() < 0.1) {
            return true
        }
        
        // Skip (other mints will handle)
        return false
    }
    
    private suspend fun validateTransaction(tx: Transaction): Boolean {
        // Check signature
        if (!verifyTransactionSignature(tx)) {
            Log.w("MobileMint", "Invalid signature: ${tx.txid}")
            return false
        }
        
        // Check for double-spend
        for (token in tx.tokens) {
            val used = db.isSerialUsed(token.serial)
            if (used) {
                // Double-spend detected!
                Log.w("MobileMint", "Double-spend detected: ${token.serial}")
                
                // Create fraud proof
                val proof = createFraudProof(tx, token.serial)
                
                // Broadcast immediately
                broadcastFraudProof(proof)
                
                return false
            }
        }
        
        // Valid transaction - store and relay
        db.storeTransaction(tx)
        
        // Mark serials as used
        for (token in tx.tokens) {
            db.markSerialUsed(token.serial, tx.txid)
        }
        
        // Relay to peers (if aggressive mode)
        if (currentMode == MintMode.AGGRESSIVE) {
            relayTransaction(tx)
        }
        
        return true
    }
}

enum class MintMode {
    STOPPED,     // Battery too low or no WiFi
    MINIMAL,     // Low battery, minimal validation
    NORMAL,      // Good battery, normal validation
    AGGRESSIVE   // Charging, maximum validation
}
```

#### iOS Implementation
```swift
import BackgroundTasks

class BeatMintManager {
    private let mint = MobileMint(wallet: walletManager)
    
    func registerBackgroundTasks() {
        // iOS is more restrictive - can only run periodically
        
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "org.beat.mint-sync",
            using: nil
        ) { task in
            self.handleMintSync(task: task as! BGProcessingTask)
        }
    }
    
    func scheduleMintSync() {
        let request = BGProcessingTaskRequest(
            identifier: "org.beat.mint-sync"
        )
        
        // Requirements
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false
        
        // Run earliest in 30 minutes
        request.earliestBeginDate = Date(timeIntervalSinceNow: 30 * 60)
        
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            print("Failed to schedule: \(error)")
        }
    }
    
    private func handleMintSync(task: BGProcessingTask) {
        // iOS gives us limited time (~30 sec to 2 min)
        
        task.expirationHandler = {
            // iOS is about to kill us - stop gracefully
            self.mint.gracefulShutdown()
        }
        
        Task {
            do {
                // Quick sync only
                try await mint.quickSync()
                
                // Validate my pending transactions
                try await mint.validateMyTransactions()
                
                // Broadcast any fraud proofs I found
                try await mint.broadcastMyFraudProofs()
                
                // Schedule next run
                scheduleMintSync()
                
                task.setTaskCompleted(success: true)
            } catch {
                print("Mint sync failed: \(error)")
                task.setTaskCompleted(success: false)
            }
        }
    }
}
```

### 6.3 Resource Optimization
```typescript
class BatteryAwareMint {
    private batteryLevel: number;
    private isCharging: boolean;
    private isWiFi: boolean;
    
    // Adjust behavior based on conditions
    updateStrategy() {
        if (this.isCharging) {
            return {
                syncInterval: 5 * 60 * 1000,        // Every 5 min
                maxPeers: 20,
                validateAll: true,
                storageLimit: 500 * 1024 * 1024    // 500 MB
            };
        }
        
        if (this.batteryLevel > 0.8) {
            return {
                syncInterval: 15 * 60 * 1000,       // Every 15 min
                maxPeers: 10,
                validateAll: true,
                storageLimit: 200 * 1024 * 1024    // 200 MB
            };
        }
        
        if (this.batteryLevel > 0.5) {
            return {
                syncInterval: 30 * 60 * 1000,       // Every 30 min
                maxPeers: 5,
                validateAll: false,                 // Sample only
                storageLimit: 100 * 1024 * 1024    // 100 MB
            };
        }
        
        if (this.batteryLevel > 0.2) {
            return {
                syncInterval: 60 * 60 * 1000,       // Every hour
                maxPeers: 2,
                validateAll: false,
                storageLimit: 50 * 1024 * 1024     // 50 MB
            };
        }
        
        // Critical battery - stop
        return {
            syncInterval: Infinity,
            maxPeers: 0,
            validateAll: false,
            storageLimit: 0
        };
    }
}
```

### 6.4 Storage Strategy
```typescript
// Mobile mint stores ONLY what's necessary

class MobileMintStorage {
    // Aggressive pruning
    
    private readonly MAX_STORAGE = 100 * 1024 * 1024; // 100 MB max
    
    async storeTransaction(tx: Transaction) {
        // Only store if locally relevant
        if (!this.isLocallyRelevant(tx)) {
            return; // Let other mints store it
        }
        
        // Check storage limit
        const currentSize = await this.getStorageSize();
        
        if (currentSize > this.MAX_STORAGE) {
            // Prune old data
            await this.pruneOldest(0.5); // Remove oldest 50%
        }
        
        // Store transaction
        await this.db.insert(tx);
    }
    
    private isLocallyRelevant(tx: Transaction): boolean {
        // Relevant if:
        // 1. I'm sender or receiver
        if (this.isMine(tx.sender) || this.isMine(tx.receiver)) {
            return true;
        }
        
        // 2. Involves my contacts
        if (this.contacts.has(tx.sender) || this.contacts.has(tx.receiver)) {
            return true;
        }
        
        // 3. Within my geographic region (optional)
        if (this.isNearby(tx)) {
            return true;
        }
        
        return false;
    }
    
    // Keep only recent data
    async pruneOldest(percentage: number) {
        const cutoffDate = Date.now() - (30 * 24 * 60 * 60 * 1000); // 30 days
        
        await this.db.deleteWhere('timestamp < ?', cutoffDate);
    }
}
```

---

## 7. Full Mint (Optional Backbone)
```typescript
// For enthusiasts who want to help the network 24/7

class FullMint {
    // No resource constraints
    
    async start() {
        // Always online
        this.p2pNode = await createFullMintNode();
        
        // Connect to many peers (50-100)
        await this.connectToManyPeers();
        
        // Subscribe to ALL topics (global reach)
        this.subscribeToAllTopics();
        
        // Provide services to mobile mints:
        // - Fast sync
        // - Historical data
        // - Transaction relay
        // - Bootstrap assistance
        
        console.log('Full mint: running 24/7');
    }
    
    // Validate everything
    async validateTransaction(tx: Transaction): Promise<boolean> {
        return await this.fullValidation(tx);
    }
    
    // Store everything
    async storeTransaction(tx: Transaction) {
        await this.db.store(tx);
    }
    
    // Help mobile mints sync quickly
    async handleSyncRequest(mobileMintPeerId: PeerId) {
        const recentData = await this.db.getRecentData();
        await this.send(mobileMintPeerId, recentData);
    }
    
    // Full mints get rewards
    getRewards(): Rewards {
        return {
            demurrageReduction: 0.5,    // 50% less demurrage
            reputation: 100,             // +100/month
            compensation: 5              // 5 BEAT/month (optional)
        };
    }
}
```

---

## 8. Transfer Protocols

### 8.1 NFC Transfer Protocol
```
┌──────────┐                    ┌──────────┐
│  Sender  │                    │ Receiver │
└────┬─────┘                    └────┬─────┘
     │                                │
     │  1. Tap phones together        │
     ├───────────────────────────────►│
     │                                │
     │  2. NFC handshake              │
     │◄──────────────────────────────►│
     │                                │
     │  3. Send transaction           │
     ├───────────────────────────────►│
     │     (NDEF message)             │
     │                                │
     │  4. Validate transaction       │
     │                                ├──┐
     │                                │  │
     │                                │◄─┘
     │                                │
     │  5. Send acknowledgment        │
     │◄───────────────────────────────┤
     │     (vibrate / sound)          │
     │                                │
     │  6. Mark tokens as spent       │
     ├──┐                             │
     │  │                             │
     │◄─┘                             │
     │                                │
     │  7. Update ownership           │
     │                             ┌──┤
     │                             │  │
     │                             └─►│
     │                                │
```

### 8.2 QR Code Transfer Protocol
```
┌──────────┐                    ┌──────────┐
│  Sender  │                    │ Receiver │
└────┬─────┘                    └────┬─────┘
     │                                │
     │  1. Receiver generates QR      │
     │                             ┌──┤
     │                             │  │
     │                             └─►│
     │                                │
     │  2. Show QR code               │
     │◄───────────────────────────────┤
     │                                │
     │  3. Sender scans QR            │
     ├──┐                             │
     │  │                             │
     │◄─┘                             │
     │                                │
     │  4. Create transaction         │
     ├──┐                             │
     │  │                             │
     │◄─┘                             │
     │                                │
     │  5. Show confirmation QR       │
     ├───────────────────────────────►│
     │     (with transaction)         │
     │                                │
     │  6. Receiver scans & validates │
     │                             ┌──┤
     │                             │  │
     │                             └─►│
     │                                │
     │  7. Show success QR            │
     │◄───────────────────────────────┤
     │                                │
```

### 8.3 Online Transfer Protocol
```
┌──────────┐    ┌──────┐    ┌──────────┐
│  Sender  │    │ Mint │    │ Receiver │
└────┬─────┘    └───┬──┘    └────┬─────┘
     │              │              │
     │  1. Create   │              │
     │  transaction │              │
     ├──┐           │              │
     │  │           │              │
     │◄─┘           │              │
     │              │              │
     │  2. Submit to mint          │
     ├─────────────►│              │
     │              │              │
     │  3. Validate │              │
     │              ├──┐           │
     │              │  │           │
     │              │◄─┘           │
     │              │              │
     │  4. Check serials           │
     │              ├──┐           │
     │              │  │           │
     │              │◄─┘           │
     │              │              │
     │  5. Broadcast to network    │
     │              ├──────────────┐
     │              │              │
     │              │◄─────────────┘
     │              │              │
     │  6. Notify receiver         │
     │              ├─────────────►│
     │              │              │
     │  7. Receiver validates      │
     │              │           ┌──┤
     │              │           │  │
     │              │           └─►│
     │              │              │
     │  8. Send confirmations      │
     │◄─────────────┤─────────────►│
     │              │              │
```

---

## 9. Sybil Resistance Through Friction

### 9.1 Core Philosophy
```
Goal: Make attack economically pointless
NOT: Make attack impossible

Strategy: Layer multiple friction points
Each individually bypassable
Together = expensive and detectable
```

### 9.2 Friction Layer 1: Gradual Activation
```typescript
// New accounts start at 10% income, grow slowly

interface ActivationSchedule {
    day1to30: 1,      // 1 BEAT/day (10%)
    day31to60: 2,     // 2 BEAT/day (20%)
    day61to90: 3,     // 3 BEAT/day (30%)
    day91to120: 5,    // 5 BEAT/day (50%)
    day121to180: 7,   // 7 BEAT/day (70%)
    day181to300: 9,   // 9 BEAT/day (90%)
    day301plus: 10    // 10 BEAT/day (100%)
}

// Can accelerate through activity
function calculateDailyAmount(
    accountAge: number,
    activityScore: number
): number {
    const baseAmount = getBaseAmount(accountAge);
    
    // Activity multiplier (up to 3x acceleration)
    const multiplier = 1 + Math.min(activityScore / 1000, 2);
    
    // Cap at 10 BEAT/day
    return Math.min(baseAmount * multiplier, 10);
}

// Activity score from:
// - Number of unique counterparties
// - Transaction diversity (not just one person)
// - Participation in community events
// - Vouching for others (carefully)
```

**Effect on attack:**
```
Without acceleration:
  20 fake accounts × 300 days = 6,000 "account-days" of waiting
  
With perfect fake activity (hard to maintain):
  Maybe 100 days to full activation
  Still 2,000 "account-days" of maintenance
  
Attacker psychology:
  Month 1: "This is tedious but doable"
  Month 3: "Still waiting... getting boring"
  Month 6: "Is this worth it?"
  Month 10: "Finally at 10 BEAT/day... and now what?"
```

### 9.3 Friction Layer 2: Voucher Limits
```typescript
interface VoucherLimits {
    // Each person can vouch for limited number per year
    maxVouchesPerYear: 5,
    
    // Must wait between vouches
    minDaysBetweenVouches: 60,
    
    // Vouchers must be established users
    minVoucherAge: 180, // 6 months
    
    // Vouchers must have activity
    minVoucherActivity: 100, // transactions
    
    // Vouchers from different clusters preferred
    diversityBonus: true
}

function canVouchFor(voucher: User, vouchee: PublicKey): boolean {
    // Check voucher eligibility
    if (voucher.accountAge < VoucherLimits.minVoucherAge) {
        return false; // Too new to vouch
    }
    
    if (voucher.activityScore < VoucherLimits.minVoucherActivity) {
        return false; // Not active enough
    }
    
    // Check voucher's recent vouches
    const recentVouches = getVouchesInLastYear(voucher);
    
    if (recentVouches.length >= VoucherLimits.maxVouchesPerYear) {
        return false; // Hit annual limit
    }
    
    const lastVouch = recentVouches[recentVouches.length - 1];
    const daysSinceLastVouch = (Date.now() - lastVouch.timestamp) / (24*60*60*1000);
    
    if (daysSinceLastVouch < VoucherLimits.minDaysBetweenVouches) {
        return false; // Too soon after last vouch
    }
    
    return true;
}
```

**Effect on attack:**
```
To create 20 fakes:
  Need: 60 vouchers (20 × 3)
  
Each voucher:
  - Must be 6+ months old
  - Must have 100+ transactions
  - Can vouch for max 5 people/year
  - Must wait 60 days between vouches
  
Math:
  20 fakes / 5 per voucher = 12 established accounts needed
  12 accounts × 6 months = 72 "account-months" of preparation
  
Alternative: Compromise 12 real accounts
  Risk: If detected, all 12 lose their real accounts
  
Attacker dilemma:
  Create fake vouchers? → Doubles the attack complexity
  Compromise real accounts? → High risk of detection
```

### 9.4 Friction Layer 3: Reputation at Stake
```typescript
interface ReputationSystem {
    // Vouchers risk their standing
    voucherPenalty: {
        voucheeDetectedAsFake: -500,  // Severe penalty
        voucheeLowActivity: -50,      // Minor penalty
        voucheeHighActivity: +10      // Small bonus
    },
    
    // Penalties affect future vouching ability
    reputationThresholds: {
        canVouch: 0,      // Need positive reputation
        canVouchMultiple: 100,
        trusted: 500
    }
}

function penalizeVoucher(voucher: User, reason: string) {
    const penalty = ReputationSystem.voucherPenalty[reason];
    
    voucher.reputation += penalty;
    
    if (voucher.reputation < 0) {
        // Negative reputation = can't vouch anymore
        voucher.canVouch = false;
        
        // Might even affect own account
        if (voucher.reputation < -1000) {
            // Extreme case: multiple fake vouches
            // Consider suspending account
            flagForReview(voucher);
        }
    }
}
```

**Effect on attack:**
```
If 1 fake detected:
  - 3 vouchers each lose -500 reputation
  - They can't vouch for others anymore
  - Their reputation tanks
  - They become suspect themselves
  
If attacker used 12 real accounts as vouchers:
  - Detection of any fake = all 12 at risk
  - Reputation cascade = all friends suspect
  - Social cost = enormous
  
Attacker calculation:
  "If I get caught, I lose not just the fake
   but also 12 real accounts I've built up.
   Is this worth it?"
```

### 9.5 Friction Layer 4: Liquidity Limits
```typescript
interface LiquidityLimits {
    // New accounts can't immediately spend large amounts
    limits: {
        day1to30: {
            maxSingleTx: 5,        // BEAT
            maxDailyTx: 10,         // BEAT
            maxMonthlyTx: 100       // BEAT
        },
        day31to90: {
            maxSingleTx: 20,
            maxDailyTx: 50,
            maxMonthlyTx: 500
        },
        day91plus: {
            maxSingleTx: 100,
            maxDailyTx: 200,
            maxMonthlyTx: 2000
        }
    }
}

function canSpend(user: User, amount: number): boolean {
    const limits = getLimitsForAge(user.accountAge);
    
    // Check single transaction limit
    if (amount > limits.maxSingleTx) {
        return false;
    }
    
    // Check daily limit
    const todaySpent = getSpentToday(user);
    if (todaySpent + amount > limits.maxDailyTx) {
        return false;
    }
    
    // Check monthly limit
    const monthSpent = getSpentThisMonth(user);
    if (monthSpent + amount > limits.maxMonthlyTx) {
        return false;
    }
    
    return true;
}
```

**Effect on attack:**
```
Even if attacker creates 20 fakes:
  Month 1: Can only spend 10 BEAT/day each = 200 BEAT/day total
  Month 3: Can only spend 50 BEAT/day each = 1000 BEAT/day total
  
But with demurrage:
  Excess above 5,000 melts
  Can't stockpile for big purchase
  Must constantly find small spenders
  
Real value extraction:
  Where to spend 1000 BEAT/day?
  Who accepts it?
  Won't prices adjust (inflation)?
  
Attacker frustration:
  "I have BEAT but can't use it effectively"
```

### 9.6 Friction Layer 5: Graph Analysis
```typescript
interface GraphAnalysis {
    // Detect suspicious patterns
    flags: {
        // Closed cluster (only vouch each other)
        isolatedCluster: {
            threshold: 0.8, // >80% internal connections
            action: 'flag_for_review'
        },
        
        // Synchronized activity (bots)
        synchronizedActivity: {
            threshold: 0.9, // >90% same times
            action: 'rate_limit'
        },
        
        // Identical behavior patterns
        behaviorSimilarity: {
            threshold: 0.95, // >95% similar
            action: 'flag_for_review'
        },
        
        // Geographic impossibility
        locationAnomaly: {
            // Same device location for multiple accounts
            action: 'immediate_flag'
        }
    }
}

async function analyzeGraph(users: User[]): Promise<SuspiciousAccounts> {
    const suspicious: User[] = [];
    
    // Build social graph
    const graph = buildSocialGraph(users);
    
    // Detect clusters
    const clusters = detectClusters(graph);
    
    for (const cluster of clusters) {
        // Calculate internal connectivity
        const internalRatio = getInternalConnectivity(cluster);
        
        if (internalRatio > 0.8) {
            // Closed cluster detected
            suspicious.push(...cluster.members);
            
            // Analyze activity patterns
            const activitySync = analyzeActivitySync(cluster.members);
            
            if (activitySync > 0.9) {
                // Likely bot farm
                cluster.members.forEach(u => {
                    u.suspicionScore += 100;
                });
            }
        }
    }
    
    // Check behavioral fingerprints
    for (const user of users) {
        const fingerprint = getBehavioralFingerprint(user);
        
        // Compare with other users
        const similar = findSimilarFingerprints(fingerprint, users);
        
        if (similar.length > 5 && similar[0].similarity > 0.95) {
            // Multiple accounts with identical behavior
            suspicious.push(user, ...similar.map(s => s.user));
        }
    }
    
    return {
        suspicious,
        clusters: clusters.filter(c => c.suspicionScore > 50),
        recommendations: generateRecommendations(suspicious)
    };
}

function getBehavioralFingerprint(user: User): Fingerprint {
    return {
        // When active
        activeHours: getActiveHours(user),
        
        // Transaction patterns
        avgTxSize: getAvgTransactionSize(user),
        txFrequency: getTransactionFrequency(user),
        
        // Counterparty diversity
        uniqueCounterparties: getUniqueCounterparties(user),
        repeatedCounterparties: getRepeatedCounterparties(user),
        
        // Device info (hashed for privacy)
        deviceFingerprint: hashDeviceInfo(user),
        
        // Geographic patterns
        locationClusters: getLocationClusters(user)
    };
}
```

**Effect on attack:**
```
If attacker creates cluster of 20 fakes:
  Week 1: Not detected (too early)
  Week 4: Graph analysis runs
    → Detects closed cluster
    → Flags for review
  Week 8: Human review
    → Confirms suspicious
    → All 20 accounts suspended
  
If attacker distributes carefully:
  Makes them vouch for real people too
  Intersperses with real activity
  Varies behavior patterns
  
  Cost: Much more complex
  Risk: Real vouches = real liability
  Time: Even longer to execute
```

### 9.7 Combined Effect
```typescript
// All layers working together

const ATTACK_COMPLEXITY = {
    layer1: 'Wait 10 months for full activation',
    layer2: 'Need 12 established vouchers',
    layer3: 'Risk losing all vouchers if caught',
    layer4: 'Limited liquidity makes extraction slow',
    layer5: 'Graph analysis will flag suspicious patterns',
    
    combined: {
        timeRequired: '10+ months minimum',
        upfrontCost: '$5,000+ (devices, time, vouchers)',
        ongoingCost: '$100+/month (maintenance)',
        detectionRisk: 'High (multiple analysis vectors)',
        exitStrategy: 'None (no fiat conversion)',
        psychologicalCost: 'Enormous (constant vigilance)',
        
        expectedReturn: {
            bestCase: '~100,000 BEAT after 1 year',
            realCase: '~50,000 BEAT (with demurrage)',
            worthInLocalEconomy: 'Limited (inflation from excess supply)',
            worthInFiat: 'Zero (no conversion possible)'
        },
        
        verdict: 'ECONOMICALLY STUPID'
    }
};
```

### 9.8 What If Attack Succeeds Anyway?
```typescript
// System self-correction mechanisms

interface SelfCorrection {
    // 1. Price discovery
    priceAdjustment: {
        mechanism: 'Local markets notice excess BEAT',
        response: 'Sellers raise prices proportionally',
        timeline: 'Weeks to months',
        result: 'Real purchasing power preserved'
    },
    
    // 2. Demurrage pressure
    demurragePressure: {
        mechanism: 'Excess BEAT melts above 5,000',
        response: 'Attackers forced to spend or lose',
        timeline: 'Continuous',
        result: 'Hoarding prevented'
    },
    
    // 3. Fireproof base protection
    baseProtection: {
        mechanism: 'First 5,000 BEAT unaffected',
        response: 'Real users retain safety net',
        result: 'Catastrophic loss prevented'
    },
    
    // 4. Community response
    communityResponse: {
        mechanism: 'Users notice suspicious activity',
        response: 'Social reputation system kicks in',
        result: 'Attackers marginalized'
    },
    
    // Acceptable damage
    acceptableDamage: {
        worstCase: '20% dilution (20 fakes among 100 real)',
        impact: '~20% local inflation',
        comparison: 'Less than typical fiat inflation',
        recovery: 'Self-correcting through price discovery'
    }
}
```

### 9.9 Design Philosophy Summary
```
Traditional approach:
  "Make attack impossible"
  → Arms race
  → Centralized verification
  → Privacy sacrificed
  
Beat approach:
  "Make attack pointless"
  → No arms race
  → Decentralized friction
  → Privacy preserved
  
Key insight:
  UBI + Demurrage = Gravitational field
  Can't steal and run
  Must constantly maintain
  Returns diminish over time
  
Result:
  Attacks possible but economically stupid
  Damage limited and self-correcting
  System remains open and decentralized
```

---

## 10. Security Model

### 10.1 Threat Model
```
Primary threats:

1. Sybil attack
   Mitigation: Friction layers (see Section 9)
   Damage if successful: Limited and self-correcting
   
2. Key compromise
   Attack: Steal seed phrase or device
   Impact: Loss of user's BEAT
   Mitigation: 
     - Secure Element storage
     - Biometric protection
     - Seed backup education
   
3. Double-spend (offline)
   Attack: Spend same token twice via NFC
   Impact: Temporary, detected quickly
   Mitigation:
     - Fraud proofs
     - Gossip propagation
     - Short detection window (minutes-hours)
   
4. Network partition
   Attack: Isolate portion of network
   Impact: Temporary inconsistency
   Mitigation:
     - Multiple connectivity paths
     - Partition detection
     - Automatic reconciliation
   
5. Privacy breach
   Attack: Link transactions to identity
   Impact: Loss of anonymity
   Mitigation:
     - ZK proofs for identity
     - P2P transfers (no central logs)
     - Optional mixing (future)

Secondary threats:

6. 51% attack on mints
   Attack: Control majority of mints in region
   Impact: Censor transactions locally
   Mitigation:
     - Diverse operators (everyone runs mint)
     - Multiple regions
     - Offline fallback (NFC)
     - Easy to detect and route around
   
7. Social engineering
   Attack: Trick users into giving seed phrase
   Impact: Account compromise
   Mitigation:
     - User education
     - No official support asking for seeds
     - App warnings
```

### 10.2 Acceptable Risks
```typescript
// Some risks are acceptable given the threat model

const ACCEPTABLE_RISKS = {
    smallScaleSybil: {
        description: '5-10 fake accounts in 1,000 users',
        impact: '0.5-1% inflation',
        why: 'Detection cost > damage cost',
        response: 'Monitor but don\'t obsess'
    },
    
    offlineDoubleSpend: {
        description: 'Spend token twice before sync',
        impact: 'Limited to <7 days, small amounts',
        why: 'Tradeoff for offline functionality',
        response: 'Fraud proof + blacklist on detection'
    },
    
    temporaryPartition: {
        description: 'Network split for hours',
        impact: 'Inconsistent state temporarily',
        why: 'Mobile network = inherently unstable',
        response: 'Automatic reconciliation when rejoined'
    },
    
    lostKeys: {
        description: 'User loses seed phrase',
        impact: 'User loses BEAT (like cash)',
        why: 'Self-custody = self-responsibility',
        response: 'Education + optional social recovery'
    }
};
```

### 10.3 Security Best Practices

#### For Users
```markdown
1. Seed Phrase
   ✓ Write down on paper (never digital)
   ✓ Store in safe place (home safe, bank vault)
   ✓ Make 2-3 copies (different locations)
   ✗ Never photograph or type on computer
   ✗ Never share with anyone
   
2. Device Security
   ✓ Set strong PIN/password
   ✓ Enable biometric lock
   ✓ Keep OS updated
   ✗ Don't root/jailbreak device
   ✗ Don't install untrusted apps
   
3. Transaction Verification
   ✓ Always verify receiver address
   ✓ Double-check amount
   ✓ Use QR codes (less error-prone)
   ✗ Don't send to unknown addresses
   
4. Backup Strategy
   ✓ Regular backups (weekly)
   ✓ Test restore process
   ✓ Encrypted cloud backup (optional)
```

#### For Mint Operators
```markdown
1. Server Security
   ✓ Firewall configured
   ✓ SSH key-only access
   ✓ Regular security updates
   ✓ DDoS protection
   ✗ Never expose database directly
   
2. Key Management
   ✓ Hardware Security Module (HSM) for mint keys
   ✓ Separate operator and mint keys
   ✓ Key rotation policy
   
3. Monitoring
   ✓ Log all suspicious activity
   ✓ Alert on fraud proofs
   ✓ Monitor peer connections
   ✓ Track resource usage
   
4. Backup
   ✓ Daily database backups
   ✓ Off-site backup storage
   ✓ Test restore regularly
```

---

## 11. Database Schemas

### 11.1 Mobile Client Database
```sql
-- SQLCipher encrypted database

CREATE TABLE wallets (
    id INTEGER PRIMARY KEY,
    identity_key BLOB NOT NULL,
    signing_key BLOB NOT NULL,
    encryption_key BLOB NOT NULL,
    account_age INTEGER NOT NULL, -- Days since creation
    activity_score INTEGER DEFAULT 0,
    reputation INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE tokens (
    serial TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    value INTEGER NOT NULL,
    issuer BLOB NOT NULL,
    current_owner BLOB NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER,
    location TEXT NOT NULL, -- 'POCKET' or 'VAULT'
    spent BOOLEAN DEFAULT 0,
    signature BLOB NOT NULL,
    raw_data BLOB NOT NULL
);

CREATE INDEX idx_tokens_location ON tokens(location);
CREATE INDEX idx_tokens_spent ON tokens(spent);

CREATE TABLE transactions (
    txid TEXT PRIMARY KEY,
    sender BLOB NOT NULL,
    receiver BLOB NOT NULL,
    amount INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    type TEXT NOT NULL, -- 'nfc', 'qr', 'online'
    memo TEXT,
    direction TEXT NOT NULL, -- 'sent' or 'received'
    validated BOOLEAN DEFAULT 0,
    raw_data BLOB NOT NULL
);

CREATE INDEX idx_transactions_timestamp ON transactions(timestamp DESC);
CREATE INDEX idx_transactions_validated ON transactions(validated);

CREATE TABLE generations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL UNIQUE, -- YYYY-MM-DD
    amount INTEGER NOT NULL, -- Actual amount (1-10 based on age)
    timestamp INTEGER NOT NULL
);

CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key BLOB NOT NULL UNIQUE,
    name TEXT,
    avatar TEXT,
    added_at INTEGER NOT NULL,
    last_interaction INTEGER
);

CREATE TABLE vouchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voucher_key BLOB NOT NULL,
    vouched_for BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    signature BLOB NOT NULL,
    status TEXT DEFAULT 'active' -- 'active', 'revoked', 'suspicious'
);

-- Mint-specific tables (for mobile mint operation)

CREATE TABLE used_serials (
    serial TEXT PRIMARY KEY,
    used_at INTEGER NOT NULL,
    transaction_id TEXT NOT NULL
);

-- Auto-cleanup old serials (>60 days)
CREATE TRIGGER cleanup_old_serials
AFTER INSERT ON used_serials
BEGIN
    DELETE FROM used_serials 
    WHERE used_at < (strftime('%s', 'now') - 5184000); -- 60 days
END;

CREATE TABLE pending_validations (
    txid TEXT PRIMARY KEY,
    raw_data BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    priority INTEGER DEFAULT 0, -- Higher = validate sooner
    attempts INTEGER DEFAULT 0
);

CREATE INDEX idx_pending_priority ON pending_validations(priority DESC, received_at ASC);

CREATE TABLE fraud_proofs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    fraudster_key BLOB NOT NULL,
    evidence BLOB NOT NULL,
    discovered_at INTEGER NOT NULL,
    broadcasted BOOLEAN DEFAULT 0
);

CREATE TABLE mint_stats (
    date TEXT PRIMARY KEY, -- YYYY-MM-DD
    transactions_validated INTEGER DEFAULT 0,
    peers_helped INTEGER DEFAULT 0,
    fraud_detected INTEGER DEFAULT 0,
    uptime_minutes INTEGER DEFAULT 0
);
```

### 11.2 Full Mint Server Database
```sql
-- PostgreSQL database

CREATE TABLE mints (
    mint_id UUID PRIMARY KEY,
    public_key BYTEA NOT NULL,
    endpoint TEXT NOT NULL,
    version TEXT NOT NULL,
    mint_type TEXT NOT NULL, -- 'mobile' or 'full'
    operator_key BYTEA NOT NULL,
    online BOOLEAN DEFAULT TRUE,
    last_seen BIGINT NOT NULL,
    uptime_percentage DECIMAL(5,2),
    validations_performed BIGINT DEFAULT 0,
    frauds_detected BIGINT DEFAULT 0,
    created_at BIGINT NOT NULL,
    reputation INTEGER DEFAULT 0
);

CREATE INDEX idx_mints_online ON mints(online);
CREATE INDEX idx_mints_type ON mints(mint_type);

CREATE TABLE used_serials (
    serial TEXT PRIMARY KEY,
    used_at BIGINT NOT NULL,
    transaction_id TEXT NOT NULL
) PARTITION BY RANGE (used_at);

-- Auto-partitioning by month for efficient cleanup
CREATE TABLE used_serials_2026_02 PARTITION OF used_serials
    FOR VALUES FROM (1706745600) TO (1709251200);

CREATE INDEX idx_used_serials_used_at ON used_serials(used_at);

CREATE TABLE fraud_proofs (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    fraudster_key BYTEA NOT NULL,
    evidence JSONB NOT NULL,
    reported_by UUID NOT NULL,
    reported_at BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (reported_by) REFERENCES mints(mint_id)
);

CREATE INDEX idx_fraud_proofs_fraudster ON fraud_proofs(fraudster_key);
CREATE INDEX idx_fraud_proofs_verified ON fraud_proofs(verified);

CREATE TABLE blacklist (
    public_key BYTEA PRIMARY KEY,
    reason TEXT NOT NULL,
    blacklisted_at BIGINT NOT NULL,
    fraud_proof_id UUID,
    FOREIGN KEY (fraud_proof_id) REFERENCES fraud_proofs(id)
);

CREATE TABLE user_commitments (
    commitment BYTEA PRIMARY KEY,
    registered_at BIGINT NOT NULL,
    last_active BIGINT NOT NULL,
    account_age INTEGER GENERATED ALWAYS AS (
        EXTRACT(DAY FROM (NOW() - TO_TIMESTAMP(registered_at)))
    ) STORED,
    activity_score INTEGER DEFAULT 0,
    reputation INTEGER DEFAULT 0,
    suspicion_score INTEGER DEFAULT 0
);

CREATE INDEX idx_commitments_last_active ON user_commitments(last_active);
CREATE INDEX idx_commitments_suspicion ON user_commitments(suspicion_score);

CREATE TABLE vouches (
    id UUID PRIMARY KEY,
    voucher_key BYTEA NOT NULL,
    vouched_commitment BYTEA NOT NULL,
    timestamp BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    status TEXT DEFAULT 'active',
    FOREIGN KEY (vouched_commitment) REFERENCES user_commitments(commitment)
);

CREATE INDEX idx_vouches_voucher ON vouches(voucher_key);
CREATE INDEX idx_vouches_status ON vouches(status);

-- Track voucher limits
CREATE TABLE vouch_limits (
    voucher_key BYTEA PRIMARY KEY,
    vouches_this_year INTEGER DEFAULT 0,
    last_vouch_at BIGINT,
    FOREIGN KEY (voucher_key) REFERENCES user_commitments(commitment)
);

CREATE TABLE checkpoints (
    height BIGINT PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    state_hash TEXT NOT NULL,
    user_count BIGINT NOT NULL,
    transaction_count BIGINT NOT NULL,
    mint_count BIGINT NOT NULL
);

CREATE TABLE transactions_log (
    txid TEXT PRIMARY KEY,
    sender BYTEA NOT NULL,
    receiver BYTEA NOT NULL,
    amount INTEGER NOT NULL,
    timestamp BIGINT NOT NULL,
    validated_by UUID NOT NULL,
    region TEXT, -- Geographic region for local filtering
    raw_data BYTEA NOT NULL,
    FOREIGN KEY (validated_by) REFERENCES mints(mint_id)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_transactions_timestamp ON transactions_log(timestamp DESC);
CREATE INDEX idx_transactions_region ON transactions_log(region);

-- Graph analysis tables
CREATE TABLE social_graph_edges (
    id UUID PRIMARY KEY,
    from_key BYTEA NOT NULL,
    to_key BYTEA NOT NULL,
    edge_type TEXT NOT NULL, -- 'vouch', 'transaction', 'contact'
    weight INTEGER DEFAULT 1,
    created_at BIGINT NOT NULL,
    FOREIGN KEY (from_key) REFERENCES user_commitments(commitment),
    FOREIGN KEY (to_key) REFERENCES user_commitments(commitment)
);

CREATE INDEX idx_graph_edges_from ON social_graph_edges(from_key);
CREATE INDEX idx_graph_edges_to ON social_graph_edges(to_key);

CREATE TABLE suspicious_clusters (
    id UUID PRIMARY KEY,
    members BYTEA[] NOT NULL,
    internal_connectivity DECIMAL(3,2), -- 0.00-1.00
    behavior_similarity DECIMAL(3,2),
    detected_at BIGINT NOT NULL,
    status TEXT DEFAULT 'under_review',
    reviewed_by TEXT,
    reviewed_at BIGINT
);

CREATE INDEX idx_clusters_status ON suspicious_clusters(status);
```

---

## 12. API Specifications
```yaml
openapi: 3.0.0
info:
  title: Beat Protocol Mint API
  version: 1.0.0
  description: REST API for Beat mint servers

servers:
  - url: https://mint.example.com/api/v1

paths:
  /validate:
    post:
      summary: Validate and submit a transaction
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Transaction'
      responses:
        '200':
          description: Transaction validated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  valid:
                    type: boolean
                  txid:
                    type: string
        '400':
          description: Invalid transaction
          content:
            application/json:
              schema:
                type: object
                properties:
                  valid:
                    type: boolean
                  error:
                    type: string

  /serial/{serial}:
    get:
      summary: Check if a serial number has been used
      parameters:
        - name: serial
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Serial status
          content:
            application/json:
              schema:
                type: object
                properties:
                  serial:
                    type: string
                  used:
                    type: boolean
                  usedAt:
                    type: integer

  /register:
    post:
      summary: Register a new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                commitment:
                  type: string
                  format: byte
                proof:
                  type: string
                  format: byte
                vouchers:
                  type: array
                  items:
                    $ref: '#/components/schemas/Voucher'
      responses:
        '200':
          description: User registered successfully
        '400':
          description: Registration failed

  /status:
    get:
      summary: Get mint server status
      responses:
        '200':
          description: Mint status
          content:
            application/json:
              schema:
                type: object
                properties:
                  online:
                    type: boolean
                  version:
                    type: string
                  peers:
                    type: integer
                  users:
                    type: integer
                  transactions:
                    type: integer

  /fraud/report:
    post:
      summary: Report suspected fraud
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                suspectKey:
                  type: string
                  format: byte
                evidence:
                  type: object
                reason:
                  type: string
      responses:
        '200':
          description: Report submitted
        '400':
          description: Invalid report

components:
  schemas:
    Transaction:
      type: object
      required:
        - txid
        - sender
        - receiver
        - amount
        - tokens
        - timestamp
        - type
        - senderSignature
      properties:
        txid:
          type: string
        sender:
          type: string
          format: byte
        receiver:
          type: string
          format: byte
        amount:
          type: integer
        tokens:
          type: array
          items:
            $ref: '#/components/schemas/Token'
        timestamp:
          type: integer
        type:
          type: string
        memo:
          type: string
        senderSignature:
          type: string
          format: byte
    
    Token:
      type: object
      properties:
        version:
          type: integer
        serial:
          type: string
        value:
          type: integer
        issuer:
          type: string
          format: byte
        currentOwner:
          type: string
          format: byte
        issuedAt:
          type: integer
        signature:
          type: string
          format: byte
    
    Voucher:
      type: object
      properties:
        voucherKey:
          type: string
          format: byte
        timestamp:
          type: integer
        signature:
          type: string
          format: byte
```

---

## 13. Deployment Guide

### 13.1 For Users (Mobile Mint)
```bash
# Users don't deploy anything - just install app

1. Download Beat app
   - Android: Play Store
   - iOS: App Store

2. Create wallet
   - App generates seed phrase
   - Write down 12 words on paper
   - Store safely (CRITICAL!)
   - Setup biometric lock

3. Get verified
   - Meet 2-3 friends already in Beat
   - NFC handshake for verification
   - System creates ZK proof

4. Start using
   - Mint automatically runs in background
   - Generate BEAT daily (starts at 1, grows to 10)
   - Spend, save, help network

No configuration needed!
Mint runs automatically when:
  ✓ Connected to WiFi
  ✓ Battery > 50%
  ✓ Screen off
```

### 13.2 For Enthusiasts (Full Mint)

#### Docker Deployment (Easiest)
```bash
# Pull and run
docker run -d \
  --name beat-mint \
  -p 8080:8080 \
  -p 9000:9000 \
  -p 9001:9001 \
  -v beat-data:/data \
  -e MINT_TYPE=full \
  -e OPERATOR_KEY=your_identity_key \
  -e BOOTSTRAP_PEERS=peer1,peer2,peer3 \
  beatprotocol/mint:latest

# Check logs
docker logs -f beat-mint

# Check status
curl http://localhost:8080/api/v1/status
```

#### From Source
```bash
# Requirements
- Ubuntu 22.04 LTS or later
- 2+ CPU cores
- 4+ GB RAM
- 50+ GB SSD
- Static IP
- Domain name (optional)

# Install dependencies
sudo apt update
sudo apt install -y nodejs npm postgresql nginx certbot

# Clone repository
git clone https://github.com/beat-protocol/mint-server.git
cd mint-server

# Install packages
npm install

# Configure PostgreSQL
sudo -u postgres psql
CREATE DATABASE beat_mint;
CREATE USER beat WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE beat_mint TO beat;
\q

# Initialize database
npm run db:migrate

# Configure environment
cp .env.example .env
nano .env

# Edit .env:
DATABASE_URL=postgresql://beat:secure_password@localhost/beat_mint
MINT_KEY=<generate with: npm run keygen>
OPERATOR_KEY=<your identity key>
PORT=8080
P2P_PORT=9000
WS_PORT=9001
BOOTSTRAP_PEERS=/dns4/boot1.beat-protocol.org/tcp/9000/p2p/...

# Build
npm run build

# Set up systemd service
sudo nano /etc/systemd/system/beat-mint.service

[Unit]
Description=Beat Protocol Mint Server
After=network.target postgresql.service

[Service]
Type=simple
User=beat
WorkingDirectory=/home/beat/mint-server
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl enable beat-mint
sudo systemctl start beat-mint

# Check status
sudo systemctl status beat-mint
```

#### Nginx Configuration
```bash
sudo nano /etc/nginx/sites-available/beat-mint

server {
    listen 80;
    server_name mint.example.com;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

# Enable site
sudo ln -s /etc/nginx/sites-available/beat-mint /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d mint.example.com
```

#### Monitoring Setup
```bash
# Install Prometheus + Grafana
sudo apt install -y prometheus grafana

# Configure Prometheus
sudo nano /etc/prometheus/prometheus.yml

global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'beat-mint'
    static_configs:
      - targets: ['localhost:8080']

# Restart Prometheus
sudo systemctl restart prometheus

# Access Grafana
# http://localhost:3000
# Default: admin/admin
```

#### Backup Setup
```bash
# Daily database backup
sudo nano /etc/cron.daily/beat-backup

#!/bin/bash
BACKUP_DIR=/backup
DATE=$(date +%Y%m%d)

# Backup database
pg_dump beat_mint | gzip > $BACKUP_DIR/beat_mint_$DATE.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -name "beat_mint_*.sql.gz" -mtime +30 -delete

# Optional: Upload to S3
# aws s3 cp $BACKUP_DIR/beat_mint_$DATE.sql.gz s3://bucket/

sudo chmod +x /etc/cron.daily/beat-backup
```

---

## 14. Testing Strategy

### 14.1 Unit Tests
```typescript
// Example: Token validation tests

import { describe, it, expect } from 'vitest';
import { createToken, signToken, verifyToken } from './token';
import { generateKeyPair } from './crypto';

describe('Token', () => {
  it('should create valid token', () => {
    const keys = generateKeyPair();
    
    const token = createToken({
      value: 10,
      issuer: keys.publicKey,
      owner: keys.publicKey
    });
    
    expect(token.version).toBe(1);
    expect(token.value).toBe(10);
    expect(token.serial).toBeDefined();
  });
  
  it('should sign and verify token', () => {
    const keys = generateKeyPair();
    
    const token = createToken({
      value: 10,
      issuer: keys.publicKey,
      owner: keys.publicKey
    });
    
    const signedToken = signToken(token, keys.secretKey);
    
    expect(verifyToken(signedToken)).toBe(true);
  });
  
  it('should reject invalid signature', () => {
    const keys1 = generateKeyPair();
    const keys2 = generateKeyPair();
    
    const token = createToken({
      value: 10,
      issuer: keys1.publicKey,
      owner: keys1.publicKey
    });
    
    // Sign with wrong key
    const signedToken = signToken(token, keys2.secretKey);
    
    expect(verifyToken(signedToken)).toBe(false);
  });
});
```

### 14.2 Integration Tests
```typescript
// Example: End-to-end transaction test

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MintServer } from './mint-server';
import { WalletManager } from './wallet';

describe('Transaction Flow', () => {
  let mint: MintServer;
  let aliceWallet: WalletManager;
  let bobWallet: WalletManager;
  
  beforeAll(async () => {
    // Start test mint server
    mint = new MintServer({ test: true });
    await mint.start();
    
    // Create test wallets
    aliceWallet = new WalletManager();
    await aliceWallet.initialize();
    
    bobWallet = new WalletManager();
    await bobWallet.initialize();
    
    // Generate tokens for Alice
    await aliceWallet.generateDailyBeat();
  });
  
  afterAll(async () => {
    await mint.stop();
  });
  
  it('should transfer tokens from Alice to Bob', async () => {
    const aliceInitial = await aliceWallet.getBalance();
    const bobInitial = await bobWallet.getBalance();
    
    expect(aliceInitial.total).toBeGreaterThan(0);
    expect(bobInitial.total).toBe(0);
    
    // Create transaction
    const tx = await aliceWallet.createTransaction(
      bobWallet.getPublicKey(),
      5,
      'Test payment'
    );
    
    // Validate
    const result = await mint.validateTransaction(tx);
    expect(result.valid).toBe(true);
    
    // Bob receives
    await bobWallet.receiveTransaction(tx);
    
    // Check balances
    const aliceFinal = await aliceWallet.getBalance();
    const bobFinal = await bobWallet.getBalance();
    
    expect(aliceFinal.total).toBe(aliceInitial.total - 5);
    expect(bobFinal.total).toBe(5);
  });
  
  it('should detect double-spend', async () => {
    await aliceWallet.generateDailyBeat();
    
    // Create two transactions with same tokens
    const tx1 = await aliceWallet.createTransaction(
      bobWallet.getPublicKey(),
      10
    );
    
    const tx2 = await aliceWallet.createTransaction(
      bobWallet.getPublicKey(),
      10
    );
    
    // First should succeed
    const result1 = await mint.validateTransaction(tx1);
    expect(result1.valid).toBe(true);
    
    // Second should fail
    const result2 = await mint.validateTransaction(tx2);
    expect(result2.valid).toBe(false);
    expect(result2.error).toContain('double-spend');
  });
});
```

### 14.3 Load Testing
```javascript
// k6 load test

import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const payload = JSON.stringify({
    txid: 'test_' + Date.now(),
    sender: '...',
    receiver: '...',
    amount: 10,
    tokens: [...],
    timestamp: Date.now(),
    type: 'online',
    senderSignature: '...'
  });
  
  const response = http.post(
    'http://localhost:8080/api/v1/validate',
    payload,
    { headers: { 'Content-Type': 'application/json' } }
  );
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time OK': (r) => r.timings.duration < 500,
  });
  
  sleep(1);
}
```

---

## 15. Performance Targets
```yaml
Mobile Mint (95% of network):
  Background CPU: <2% average
  RAM: <50 MB
  Storage: <100 MB total
  Battery: <1% per hour drain
  Network: <10 MB/day (WiFi only)
  Validation: <500ms per transaction
  Sync interval: 5-60 minutes (adaptive)

Full Mint (5% of network):
  CPU: <25% (2 cores)
  RAM: <500 MB
  Storage: <1 GB per 10,000 users
  Bandwidth: <1 GB/day
  Validation: <100ms per transaction
  Uptime: >99%
  Max connections: 100

Network Overall:
  Active mints: >1,000 (for 10,000 users)
  Redundancy: 5-10x (multiple validations per tx)
  Double-spend detection: <5 min (local), <30 min (global)
  Fraud proof propagation: <1 hour (global)
  Partition tolerance: >50% offline = still works
  Attack detection: <1 week (graph analysis)
  
Scalability:
  10,000 users: Proven architecture
  100,000 users: Regional sharding needed
  1,000,000 users: Full sharding + optimization
```

---

## 16. Future Enhancements

### Phase 1 (Current - v1.0)
- Basic token generation
- NFC transfers
- Mobile mints (primary)
- Fixed demurrage
- Simple fraud detection

### Phase 2 (6-12 months - v1.5)
- Full mint federation (gossip)
- Complete ZK proof implementation
- Progressive demurrage active
- iOS app
- QR code transfers
- Graph analysis tools

### Phase 3 (12-24 months - v2.0)
- Mesh networking (full offline)
- Token mixing (enhanced privacy)
- Multi-signature escrow
- Advanced reputation system
- Web interface
- Hardware wallet support

### Phase 4 (24+ months - v3.0)
- Lightning-style payment channels
- Atomic swaps (with other currencies)
- DAO governance
- Cross-chain bridges (if needed)
- AI-assisted fraud detection

---

## 17. Open Questions

Questions requiring community input:

1. **ZK Proof System**
   - Bulletproofs vs Groth16 vs STARKs?
   - Trade-off: proof size vs verification time

2. **Demurrage Application**
   - Applied continuously (daily) or monthly?
   - What happens to "melted" BEAT? (destroyed or redistributed?)

3. **Voucher Expiry**
   - Do vouchers expire?
   - Can vouchers be revoked if vouchee misbehaves?

4. **Mint Incentives**
   - Is 50% demurrage reduction enough?
   - Should there be additional rewards?

5. **Token Denominations**
   - Currently: 10, 5, 1 BEAT
   - Should we support fractional (0.1, 0.5)?

6. **Privacy vs Auditability**
   - How much transaction privacy is too much?
   - Should there be optional transparency mode?

7. **Governance**
   - How to make protocol upgrades?
   - On-chain voting? Informal consensus?

8. **Interoperability**
   - Should Beat integrate with other currencies?
   - Atomic swaps? Bridges?

---

## 18. Contributing

This specification is a living document.

**To contribute:**
1. Open an issue for discussion
2. Submit a pull request with proposed changes
3. Join technical working group meetings
4. Review and comment on others' proposals

**Contact:**
- GitHub: github.com/beat-protocol/technical-spec
- Forum: forum.beat-protocol.org/c/technical
- Email: tech@beat-protocol.org

---

## 19. Conclusion

### 19.1 Key Innovations
```
1. Every smartphone = mint
   → True decentralization
   → Scales automatically with users
   → No "mining" inequality

2. Attack through friction, not impossibility
   → Economically stupid to attack
   → Self-correcting if attack succeeds
   → Preserves openness and privacy

3. UBI + Demurrage = Gravitational field
   → Can't hoard
   → Must circulate
   → Ongoing maintenance required
   → No exit strategy for attackers

4. Mobile-first architecture
   → Battery-conscious
   → Resource-aware
   → Works on old phones
   → Optional full nodes for enthusiasts

5. Acceptable trade-offs
   → Some attacks possible
   → Damage limited and temporary
   → System self-balances
   → Focus on what matters
```

### 19.2 What Makes This Different
```
vs Bitcoin:
  - No mining (equal for all)
  - Mobile-friendly (not power-hungry)
  - Circulation-focused (not hoarding)
  - Attack = dilution (not theft)

vs Ethereum:
  - No gas fees (free transactions)
  - No smart contracts (simpler)
  - Privacy-first (ZK from start)
  - Every user = validator

vs Traditional UBI:
  - Decentralized (no central issuer)
  - Global (works anywhere)
  - Private (no tracking)
  - Built-in economic incentives

Beat = UBI + P2P + Privacy + Mobile-first
```

### 19.3 Success Criteria
```
Technical success:
  - 10,000+ users
  - 99%+ uptime
  - <5 min double-spend detection
  - <1% Sybil accounts

Economic success:
  - Real goods/services exchanged
  - Local price discovery working
  - Demurrage driving circulation
  - Fireproof base provides security

Social success:
  - Communities self-organizing
  - Trust networks forming
  - Alternative to fiat in niches
  - Proof that alternatives possible
```

---

**END OF TECHNICAL SPECIFICATION v1.1**

**Status:** Concept Phase  
**Version:** 1.1  
**Date:** February 15, 2026  
**License:** MIT (fully open source)


♥ Keep the beat alive.
