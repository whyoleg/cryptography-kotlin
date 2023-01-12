package dev.whyoleg.cryptography.webcrypto.operations

import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.webcrypto.*
import dev.whyoleg.cryptography.webcrypto.external.*

internal class WebCryptoSignatureGenerator(
    private val algorithm: SignAlgorithm,
    private val key: CryptoKey,
) : SignatureGenerator {
    override suspend fun generateSignature(dataInput: Buffer): Buffer {
        return WebCrypto.subtle.sign(algorithm, key, dataInput).await().toByteArray()
    }

    override fun generateSignatureBlocking(dataInput: Buffer): Buffer = nonBlocking()
}
