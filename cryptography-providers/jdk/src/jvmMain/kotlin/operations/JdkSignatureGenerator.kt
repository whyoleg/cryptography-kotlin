/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations


import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import java.security.spec.*

internal class JdkSignatureGenerator(
    private val state: JdkCryptographyState,
    private val key: JPrivateKey,
    algorithm: String,
    private val parameters: AlgorithmParameterSpec?,
) : SignatureGenerator {
    private val signature = state.signature(algorithm)
    override fun createSignFunction(): SignFunction = JdkSignFunction(signature.borrowResource().also {
        val jsignature = it.access()
        jsignature.initSign(key, state.secureRandom)
        parameters?.let(jsignature::setParameter)
    })
}

private class JdkSignFunction(private val jsignature: Pooled.Resource<JSignature>) : SignFunction {
    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        checkBounds(source.size, startIndex, endIndex)
        val jsignature = jsignature.access()
        jsignature.update(source, startIndex, endIndex - startIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val signature = signToByteArray()
        checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
        signature.copyInto(destination, destinationOffset, destinationOffset)
        return signature.size
    }

    override fun signToByteArray(): ByteArray {
        val jsignature = jsignature.access()
        return jsignature.sign().also { close() }
    }

    override fun close() {
        jsignature.close()
    }
}
