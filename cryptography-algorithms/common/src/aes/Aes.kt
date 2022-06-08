package dev.whyoleg.cryptography.aes

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public sealed class AesKeyGenerationParameters<K : AesKey>(
    keySize: KeySize
) : SecretKeyGenerationParameters<K>(keySize) {
    init {
        require(
            keySize.hasSizeOf(128.bits) ||
                    keySize.hasSizeOf(196.bits) ||
                    keySize.hasSizeOf(256.bits)
        )
    }
}

public sealed class AesKeyImportParameters<K : AesKey> : KeyImportParameters<K>

public interface AesKey : SecretKey
