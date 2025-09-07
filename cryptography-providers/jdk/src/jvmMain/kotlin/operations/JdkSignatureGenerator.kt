/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.jdk.*
import java.security.spec.*

internal class JdkSignatureGenerator(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureGenerator {
    private val signature = state.signature(algorithm)
    override fun createSignFunction(): SignFunction = JdkSignFunction(state, key, parameters, signature.borrowResource())
}

private class JdkSignFunction(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    private val parameters: AlgorithmParameterSpec?,
    private val jsignature: Pooled.Resource<JSignature>,
) : SignFunction {
    init {
        reset()
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)
        val jsignature = jsignature.access()
        jsignature.update(source, startIndex, endIndex - startIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val signature = signToByteArray()
        checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
        signature.copyInto(destination, destinationOffset, 0, signature.size)
        return signature.size
    }

    override fun signToByteArray(): ByteArray {
        val jsignature = jsignature.access()
        return jsignature.sign()
    }

    override fun reset() {
        val jsignature = jsignature.access()
        jsignature.initSign(key, state.secureRandom)
        parameters?.let(jsignature::setParameter)
    }

    override fun close() {
        jsignature.close()
    }
}
