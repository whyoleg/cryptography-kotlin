package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.key.*
import java.security.*

internal class AesGcm(
    private val state: JdkCryptographyState,
) : AES.GCM() {
    override fun syncKeyGenerator(parameters: SymmetricKeyParameters): SyncKeyGenerator<Key> =
        AesGcmKeyGenerator(state, parameters.size.value.bits)

    override fun asyncKeyGenerator(parameters: SymmetricKeyParameters): AsyncKeyGenerator<Key> {
        TODO("Not yet implemented")
    }
}

internal class AesCbc(
    private val state: JdkCryptographyState,
) : AES.CBC() {
    override fun syncKeyGenerator(parameters: SymmetricKeyParameters): SyncKeyGenerator<Key> =
        AesCbcKeyGenerator(state, parameters.size.value.bits)

    override fun asyncKeyGenerator(parameters: SymmetricKeyParameters): AsyncKeyGenerator<Key> {
        TODO("Not yet implemented")
    }
}

