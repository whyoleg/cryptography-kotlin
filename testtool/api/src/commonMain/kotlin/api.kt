/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.testtool.api

import kotlinx.serialization.*
import kotlinx.serialization.cbor.*

@Serializable
sealed class Operation

@Serializable
sealed class OperationResult

@Serializable
sealed class SaveOperation : Operation() {
    abstract val id: String
}

@Serializable
sealed class GetOperation : Operation() {
    abstract val requestId: String
}

@Serializable
sealed class GetOperationResult : OperationResult() {
    abstract val requestId: String
}

@Suppress("ArrayInDataClass")
@Serializable
data class SaveParameters(
    override val id: String,
    val algorithm: String,
    val path: String,
    val payload: ByteArray,
) : SaveOperation() {
    override fun toString(): String = "SaveParameters($algorithm/$path: ${payload.size} bytes)"
}

@Serializable
data class GetParameters(
    override val requestId: String,
    val algorithm: String,
    val path: String,
) : GetOperation() {
    override fun toString(): String = "GetParameters($algorithm/$path)"
}

@Suppress("ArrayInDataClass")
@Serializable
data class SaveData(
    override val id: String,
    val algorithm: String,
    val path: String,
    val parametersId: String,
    val payload: ByteArray,
) : SaveOperation() {
    override fun toString(): String = "SaveData($algorithm/$path/$parametersId: ${payload.size} bytes)"
}

@Serializable
data class GetData(
    override val requestId: String,
    val algorithm: String,
    val path: String,
    val parametersId: String,
) : GetOperation() {
    override fun toString(): String = "GetData($algorithm/$path/$parametersId)"
}

@Suppress("ArrayInDataClass")
@Serializable
data class GetOperationResultItem(
    override val requestId: String,
    val id: String,
    val payload: ByteArray,
) : GetOperationResult() {
    override fun toString(): String = "GetOperationItem($id: ${payload.size} bytes)"
}

@Serializable
data class GetOperationResultDone(override val requestId: String) : GetOperationResult()

@OptIn(ExperimentalSerializationApi::class)
val ConfiguredCbor = Cbor {
    alwaysUseByteString = true
}
