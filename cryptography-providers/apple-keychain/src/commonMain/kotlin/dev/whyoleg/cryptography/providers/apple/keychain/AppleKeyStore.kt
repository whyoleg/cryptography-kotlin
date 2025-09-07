@file:OptIn(
    kotlinx.cinterop.UnsafeNumber::class,
    kotlinx.cinterop.ExperimentalForeignApi::class,
    dev.whyoleg.cryptography.storage.ExperimentalKeyStorageApi::class,
)

package dev.whyoleg.cryptography.providers.apple.keychain

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.storage.*
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*

@OptIn(ExperimentalForeignApi::class)
@ExperimentalKeyStorageApi
public object AppleKeyStore : KeyStore {
    override fun ecdsa(curve: EC.Curve): AsymmetricStore<ECDSA.PublicKey, ECDSA.PrivateKey> {
        // MVP: support P-256 only
        require(curve == EC.Curve.P256) { "Unsupported curve: ${curve.name}" }
        return AppleEcdsaStore(curve)
    }

    override fun rsaPss(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>
    ): AsymmetricStore<RSA.PSS.PublicKey, RSA.PSS.PrivateKey> {
        throw UnsupportedOperationException("RSA-PSS not implemented in MVP")
    }

    override fun rsaPkcs1(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>
    ): AsymmetricStore<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey> {
        throw UnsupportedOperationException("RSA-PKCS1 not implemented in MVP")
    }

    override fun rsaOaep(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>
    ): AsymmetricStore<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey> {
        throw UnsupportedOperationException("RSA-OAEP not implemented in MVP")
    }

    override fun aesGcm(size: BinarySize): SymmetricStore<AES.GCM.Key> {
        throw UnsupportedOperationException("AES-GCM not implemented in MVP")
    }

    override fun aesCbc(size: BinarySize): SymmetricStore<AES.CBC.Key> {
        throw UnsupportedOperationException("AES-CBC not implemented in MVP")
    }

    override fun aesCtr(size: BinarySize): SymmetricStore<AES.CTR.Key> {
        throw UnsupportedOperationException("AES-CTR not implemented in MVP")
    }
}

@OptIn(ExperimentalForeignApi::class)
@ExperimentalKeyStorageApi
private class AppleEcdsaStore(private val curve: EC.Curve) : AsymmetricStore<ECDSA.PublicKey, ECDSA.PrivateKey> {
    override fun generate(label: ByteArray, access: AccessPolicy): Handle<ECDSA.PublicKey, ECDSA.PrivateKey> = memScoped {
        val accessCtrl = createAccessControl(access)
        val attrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        // key attributes
        CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        // P-256 only in MVP
        CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, cfNumber(256))
        CFDictionarySetValue(attrs, kSecAttrIsPermanent, kCFBooleanTrue)
        CFDictionarySetValue(attrs, kSecAttrAccessControl, accessCtrl)
        CFDictionarySetValue(attrs, kSecAttrApplicationTag, label.toCFData())
        // optional human-readable label: omitted for compatibility

        val errRef = alloc<CFErrorRefVar>()
        val priv = SecKeyCreateRandomKey(attrs, errRef.ptr)
            ?: run {
                CFRelease(attrs); CFRelease(accessCtrl)
                error(cfErrorMessage(errRef.value))
            }
        val pub = SecKeyCopyPublicKey(priv) ?: run {
            CFRelease(attrs); CFRelease(accessCtrl); CFRelease(priv)
            error("pub_key_null")
        }
        val pubKey: ECDSA.PublicKey = AppleEcdsaPublicKey(pub)
        val privKey: ECDSA.PrivateKey = AppleEcdsaPrivateKey(priv)
        CFRelease(attrs); CFRelease(accessCtrl)
        Handle(public = pubKey, private = privKey, attributes = KeyAttributes(extractable = false, persistent = true, label = label))
    }

    override fun get(label: ByteArray): Handle<ECDSA.PublicKey, ECDSA.PrivateKey>? = memScoped {
        val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        CFDictionarySetValue(query, kSecAttrApplicationTag, label.toCFData())
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue)
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
        val out = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, out.ptr)
        if (status != errSecSuccess) { CFRelease(query); return null }
        @Suppress("UNCHECKED_CAST")
        val priv = out.value as SecKeyRef
        val pub = SecKeyCopyPublicKey(priv) ?: run { CFRelease(priv); CFRelease(query); return null }
        val handle: Handle<ECDSA.PublicKey, ECDSA.PrivateKey> = Handle(public = AppleEcdsaPublicKey(pub), private = AppleEcdsaPrivateKey(priv), attributes = KeyAttributes(false, true, label))
        CFRelease(query)
        handle
    }

    override fun exists(label: ByteArray): Boolean = memScoped {
        val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        CFDictionarySetValue(query, kSecAttrApplicationTag, label.toCFData())
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
        val ok = SecItemCopyMatching(query, null) == errSecSuccess
        CFRelease(query)
        ok
    }

    override fun delete(label: ByteArray): Boolean = memScoped {
        val query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
        CFDictionarySetValue(query, kSecAttrApplicationTag, label.toCFData())
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue)
        val status = SecItemDelete(query)
        CFRelease(query)
        status == errSecSuccess || status == errSecItemNotFound
    }
}

// --- ECDSA key wrappers (DER format support; RAW not supported in MVP) ---

@OptIn(ExperimentalForeignApi::class)
private class AppleEcdsaPublicKey(private val key: SecKeyRef) : ECDSA.PublicKey {

    override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureVerifier {
        require(format == ECDSA.SignatureFormat.DER) { "Only DER signatures supported in MVP" }
        return object : SignatureVerifier {
            override fun createVerifyFunction(): VerifyFunction = object : VerifyFunction {
                private var acc = ByteArray(0)
                private var closed = false
                override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
                    check(!closed) { "Already closed" }
                    acc += source.copyOfRange(startIndex, endIndex)
                }
                override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean = memScoped {
                    check(!closed) { "Already closed" }
                    val error = alloc<CFErrorRefVar>()
                    val ok = acc.useNSData { data ->
                        signature.useNSData(startIndex, endIndex) { sig ->
                            SecKeyVerifySignature(
                                key = key,
                                algorithm = digest.ecdsaSecKeyAlgorithm(),
                                signedData = data.retainBridgeAs<CFDataRef>(),
                                error = error.ptr,
                                signature = sig.retainBridgeAs<CFDataRef>()
                            )
                        }
                    }
                    acc = ByteArray(0)
                    ok
                }
                override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
                    if (!tryVerify(signature, startIndex, endIndex)) error("Invalid signature")
                }
                override fun reset() { acc = ByteArray(0); closed = false }
                override fun close() { closed = true; acc = ByteArray(0) }
            }
        }
    }

    override fun encodeToByteArrayBlocking(format: EC.PublicKey.Format): ByteArray {
        val raw = exportKey(key)
        return when (format) {
            EC.PublicKey.Format.JWK            -> error("JWK not supported")
            EC.PublicKey.Format.RAW            -> raw
            EC.PublicKey.Format.RAW.Compressed -> error("Compressed RAW not supported")
            EC.PublicKey.Format.DER            -> encodeSpki(raw)
            EC.PublicKey.Format.PEM            -> encodeSpki(raw).wrapPem("PUBLIC KEY")
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private class AppleEcdsaPrivateKey(private val key: SecKeyRef) : ECDSA.PrivateKey {

    override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>, format: ECDSA.SignatureFormat): SignatureGenerator {
        require(format == ECDSA.SignatureFormat.DER) { "Only DER signatures supported in MVP" }
        return object : SignatureGenerator {
            override fun createSignFunction(): SignFunction = object : SignFunction {
                private var acc = ByteArray(0)
                private var closed = false
                override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
                    check(!closed) { "Already closed" }
                    acc += source.copyOfRange(startIndex, endIndex)
                }
                override fun signToByteArray(): ByteArray = memScoped {
                    check(!closed) { "Already closed" }
                    val error = alloc<CFErrorRefVar>()
                    val signature = acc.useNSData { data ->
                        SecKeyCreateSignature(
                            key = key,
                            algorithm = digest.ecdsaSecKeyAlgorithm(),
                            dataToSign = data.retainBridgeAs<CFDataRef>(),
                            error = error.ptr
                        )?.releaseBridgeAs<NSData>()
                    }
                    if (signature == null) error(cfErrorMessage(error.value))
                    acc = ByteArray(0)
                    signature.toByteArray()
                }
                override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
                    val s = signToByteArray()
                    s.copyInto(destination, destinationOffset)
                    return s.size
                }
                override fun reset() { acc = ByteArray(0); closed = false }
                override fun close() { closed = true; acc = ByteArray(0) }
            }
        }
    }

    override fun encodeToByteArrayBlocking(format: EC.PrivateKey.Format): ByteArray {
        error("Private key export is disabled for non-extractable keys")
    }
}

// --- Helpers ---

private fun CryptographyAlgorithmId<Digest>.ecdsaSecKeyAlgorithm(): SecKeyAlgorithm? = when (this) {
    SHA1   -> kSecKeyAlgorithmECDSASignatureMessageX962SHA1
    SHA224 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA224
    SHA256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
    SHA384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
    SHA512 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
    else   -> null
}

private fun encodeSpki(rawUncompressedPoint: ByteArray): ByteArray {
    // Minimal SPKI encoder: 0x30 SEQ(alg + bitstring)
    // For MVP we construct ASN.1 DER via simple concatenation since sizes are fixed for P-256
    // AlgorithmIdentifier for EC P-256: 06 08 2A 86 48 CE 3D 02 01 (id-ecPublicKey)
    // parameters = 06 08 2A 86 48 CE 3D 03 01 07 (secp256r1)
    val alg = byteArrayOf(
        0x30, 0x13, // SEQUENCE len 19
        0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07
    )
    val bitStringHeader = byteArrayOf(0x03, (rawUncompressedPoint.size + 1).toByte(), 0x00)
    val body = alg + bitStringHeader + rawUncompressedPoint
    val header = byteArrayOf(0x30, body.size.toByte())
    return header + body
}

private fun ByteArray.wrapPem(label: String): ByteArray {
    val base64 = kotlin.io.encoding.Base64.encode(this)
    val lines = base64.chunked(64).joinToString("\n")
    val pem = "-----BEGIN $label-----\n$lines\n-----END $label-----\n"
    return pem.encodeToByteArray()
}

@OptIn(ExperimentalForeignApi::class)
private fun <T> ByteArray.useCFData(block: (CFDataRef?) -> T): T = memScoped {
    this@useCFData.usePinned { pin ->
        val d = CFDataCreate(kCFAllocatorDefault, pin.addressOf(0).reinterpret(), size.convert())
        try { return block(d) } finally { if (d != null) CFRelease(d) }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun exportKey(key: SecKeyRef): ByteArray = memScoped {
    val err = alloc<CFErrorRefVar>()
    val data = SecKeyCopyExternalRepresentation(key, err.ptr)?.releaseBridgeAs<NSData>()
    if (data == null) error(cfErrorMessage(err.value))
    data.toByteArray()
}

@OptIn(ExperimentalForeignApi::class)
private fun ByteArray.toCFData(): CFDataRef? = memScoped {
    this@toCFData.usePinned { pin -> CFDataCreate(kCFAllocatorDefault, pin.addressOf(0).reinterpret(), size.convert()) }
}

// string label helper removed (not used)

@OptIn(ExperimentalForeignApi::class)
private fun createAccessControl(policy: AccessPolicy): SecAccessControlRef? = memScoped {
    val flags = (kSecAccessControlPrivateKeyUsage) or (if (policy.requireUserPresence) kSecAccessControlUserPresence else 0u)
    val err = alloc<CFErrorRefVar>()
    val ac = SecAccessControlCreateWithFlags(
        allocator = kCFAllocatorDefault,
        protection = when (policy.accessibility) {
            Accessibility.WhenUnlocked -> kSecAttrAccessibleWhenUnlocked
            Accessibility.AfterFirstUnlock -> kSecAttrAccessibleAfterFirstUnlock
            Accessibility.Always -> kSecAttrAccessibleAlways
            Accessibility.WhenPasscodeSetThisDeviceOnly -> kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        },
        flags = flags,
        error = err.ptr
    )
    if (ac == null) error(cfErrorMessage(err.value))
    ac
}

@OptIn(ExperimentalForeignApi::class)
private fun cfErrorMessage(e: CFErrorRef?): String {
    if (e == null) return "error"
    val desc = CFErrorCopyDescription(e)
    val ns = (desc as CFTypeRef?).releaseBridgeAs<platform.Foundation.NSString>()
    return ns?.toString() ?: "error"
}

@Suppress("UNCHECKED_CAST")
private fun <T : Any> Any?.retainBridgeAs(): T? = CFBridgingRetain(this)?.let { it as T }

@Suppress("UNCHECKED_CAST")
private fun <T : Any> CFTypeRef?.releaseBridgeAs(): T? = CFBridgingRelease(this)?.let { it as T }

@OptIn(ExperimentalForeignApi::class)
private fun cfNumber(i: Int): CFNumberRef? = memScoped {
    CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, cValuesOf(i))
}
