/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations


import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal class JdkSignatureGenerator(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureGenerator {
    private val signature = state.signature(algorithm)

    override fun generateSignatureBlocking(data: ByteArray): ByteArray = signature.use { jSignature ->
        jSignature.initSign(key, state.secureRandom)
        parameters?.let(jSignature::setParameter)
        jSignature.update(data)
        jSignature.sign()
    }
}
