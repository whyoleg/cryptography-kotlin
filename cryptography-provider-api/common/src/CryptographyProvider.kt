package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

//supported: several Hashes, Aes(ctr, cbc, gcm), Rsa(oaep, pss), Hmac

public interface CryptographyProvider {
    public fun hash(parameters: HashParameters): Hash

    public fun <K : Key> generateKey(parameters: KeyGenerationParameters<K>): K

    public fun <K : SecretKey> importKey(
        format: SecretKeyFormat,
        input: BufferView,
        parameters: KeyImportParameters<K>
    ): K

    public fun <K : KeyPair> importKey(
        format: KeyPairFormat,
        input: BufferView,
        parameters: KeyImportParameters<K>
    ): K

    public fun <K : PublicKey> importKey(
        format: PublicKeyFormat,
        input: BufferView,
        parameters: KeyImportParameters<K>
    ): K

    public fun <K : PrivateKey> importKey(
        format: PrivateKeyFormat,
        input: BufferView,
        parameters: KeyImportParameters<K>
    ): K
}
