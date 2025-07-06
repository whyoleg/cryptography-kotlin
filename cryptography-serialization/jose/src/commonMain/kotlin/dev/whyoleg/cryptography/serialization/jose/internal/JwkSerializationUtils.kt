/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.internal

import dev.whyoleg.cryptography.serialization.jose.*
import kotlinx.serialization.json.*

/**
 * Common utilities for JsonWebKey serialization.
 */
internal object JwkSerializationUtils {
    
    /**
     * Standard JWK field names that should not be included in additional parameters.
     */
    val standardFields = setOf(
        "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
        "n", "e", "d", "p", "q", "dp", "dq", "qi", // RSA
        "crv", "x", "y", // EC
        "k" // Symmetric
    )
    
    /**
     * Extracts common JWK parameters from a JSON object.
     */
    fun extractCommonParameters(element: JsonObject): CommonJwkParameters {
        return CommonJwkParameters(
            keyUse = element["use"]?.jsonPrimitive?.content?.let { JwkKeyUse(it) },
            keyOperations = element["key_ops"]?.jsonArray?.map { JwkKeyOperation(it.jsonPrimitive.content) },
            algorithm = element["alg"]?.jsonPrimitive?.content?.let { JwsAlgorithm(it) },
            keyId = element["kid"]?.jsonPrimitive?.content,
            x509Url = element["x5u"]?.jsonPrimitive?.content,
            x509CertificateChain = element["x5c"]?.jsonArray?.map { it.jsonPrimitive.content },
            x509CertificateSha1Thumbprint = element["x5t"]?.jsonPrimitive?.content,
            x509CertificateSha256Thumbprint = element["x5t#S256"]?.jsonPrimitive?.content,
            additionalParameters = element.filterKeys { it !in standardFields }
        )
    }
    
    /**
     * Adds common JWK fields to a JSON object builder.
     */
    fun JsonObjectBuilder.addCommonFields(value: JsonWebKey) {
        value.keyUse?.let { put("use", JsonPrimitive(it.value)) }
        value.keyOperations?.let { ops -> put("key_ops", JsonArray(ops.map { JsonPrimitive(it.value) })) }
        value.algorithm?.let { put("alg", JsonPrimitive(it.value)) }
        value.keyId?.let { put("kid", JsonPrimitive(it)) }
        value.x509Url?.let { put("x5u", JsonPrimitive(it)) }
        value.x509CertificateChain?.let { chain -> put("x5c", JsonArray(chain.map { JsonPrimitive(it) })) }
        value.x509CertificateSha1Thumbprint?.let { put("x5t", JsonPrimitive(it)) }
        value.x509CertificateSha256Thumbprint?.let { put("x5t#S256", JsonPrimitive(it)) }
        value.additionalParameters.forEach { (key, value) -> put(key, value) }
    }
}

/**
 * Common JWK parameters extracted from JSON.
 */
internal data class CommonJwkParameters(
    val keyUse: JwkKeyUse?,
    val keyOperations: List<JwkKeyOperation>?,
    val algorithm: JwsAlgorithm?,
    val keyId: String?,
    val x509Url: String?,
    val x509CertificateChain: List<String>?,
    val x509CertificateSha1Thumbprint: String?,
    val x509CertificateSha256Thumbprint: String?,
    val additionalParameters: Map<String, JsonElement>
)