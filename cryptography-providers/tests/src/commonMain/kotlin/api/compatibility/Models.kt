/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api.compatibility

import kotlinx.serialization.*
import kotlin.jvm.*

interface TestParameters {
    @Serializable
    object Empty : TestParameters {
        override fun toString(): String = "EmptyParameters"
    }
}

interface TestData

@Serializable
@JvmInline
value class TestParametersId(val value: String) {
    override fun toString(): String = "P($value)"
}

@Serializable
@JvmInline
value class TestDataId(val value: String) {
    override fun toString(): String = "D($value)"
}

@Serializable
data class TestReference(
    val parametersId: TestParametersId,
    val dataId: TestDataId,
) {
    override fun toString(): String = "R(${parametersId.value} -> ${dataId.value})"
}

@Serializable
data class DigestData(
    val data: ByteStringAsString,
    val digest: ByteStringAsString,
) : TestData

@Serializable
data class KeyData(
    val formats: Map<String, ByteStringAsString>,
) : TestData

@Serializable
data class KeyPairData(
    val public: KeyData,
    val private: KeyData,
) : TestData

@Serializable
data class CipherData(
    val keyReference: TestReference,
    val plaintext: ByteStringAsString,
    val ciphertext: ByteStringAsString,
) : TestData

@Serializable
data class AuthenticatedCipherData(
    val keyReference: TestReference,
    val associatedData: ByteStringAsString?,
    val plaintext: ByteStringAsString,
    val ciphertext: ByteStringAsString,
) : TestData

@Serializable
data class SignatureData(
    val keyReference: TestReference,
    val data: ByteStringAsString,
    val signature: ByteStringAsString,
) : TestData

@Serializable
data class SharedSecretData(
    val keyReference: TestReference,
    val otherKeyReference: TestReference,
    val sharedSecret: ByteStringAsString,
) : TestData

@Serializable
data class DerivedSecretData(
    val input: ByteStringAsString,
    val secret: ByteStringAsString,
) : TestData
