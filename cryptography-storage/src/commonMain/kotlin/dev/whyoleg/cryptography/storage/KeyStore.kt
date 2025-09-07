package dev.whyoleg.cryptography.storage

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*

/**
 * Entry point for provider-backed key storage.
 *
 * Implementations expose algorithm-typed stores that can generate, fetch, and delete
 * persistent keys under binary-safe labels and enforce [AccessPolicy]. Returned handles
 * integrate with existing algorithm APIs (e.g., ECDSA/RSA/AES) without exporting private material
 * when keys are non-extractable.
 */
@ExperimentalKeyStorageApi
public interface KeyStore {
    /** ECDSA key store for the given [curve] (default P-256). */
    public fun ecdsa(curve: EC.Curve = EC.Curve.P256): AsymmetricStore<ECDSA.PublicKey, ECDSA.PrivateKey>

    // RSA families
    /** RSA-PSS key store configured with [keySize] and [digest]. */
    public fun rsaPss(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
    ): AsymmetricStore<RSA.PSS.PublicKey, RSA.PSS.PrivateKey>

    /** RSA-PKCS1 v1.5 key store configured with [keySize] and [digest]. */
    public fun rsaPkcs1(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
    ): AsymmetricStore<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey>

    /** RSA-OAEP key store configured with [keySize] and [digest]. */
    public fun rsaOaep(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
    ): AsymmetricStore<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey>

    // AES families
    /** AES-GCM key store. */
    public fun aesGcm(size: BinarySize = AES.Key.Size.B256): SymmetricStore<AES.GCM.Key>
    /** AES-CBC key store. */
    public fun aesCbc(size: BinarySize = AES.Key.Size.B256): SymmetricStore<AES.CBC.Key>
    /** AES-CTR key store. */
    public fun aesCtr(size: BinarySize = AES.Key.Size.B256): SymmetricStore<AES.CTR.Key>
    // ECB is deliberately excluded due to DelicateCryptographyApi
}
