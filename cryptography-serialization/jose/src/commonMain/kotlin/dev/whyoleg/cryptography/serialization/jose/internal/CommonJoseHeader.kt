/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.internal

import dev.whyoleg.cryptography.serialization.jose.JsonWebKey
import kotlinx.serialization.json.JsonElement

/**
 * Common header parameters shared across JOSE specifications.
 */
internal interface CommonJoseHeader {
    /** JWS and JWE Type parameter */
    val type: String?
    /** Content Type parameter */
    val contentType: String?
    /** Key ID hint indicating which key was used to secure the token */
    val keyId: String?
    /** JSON Web Key parameter */
    val jsonWebKey: JsonWebKey?
    /** X.509 URL parameter */
    val x509Url: String?
    /** X.509 Certificate Chain parameter */
    val x509CertificateChain: List<String>?
    /** X.509 Certificate SHA-1 Thumbprint parameter */
    val x509CertificateSha1Thumbprint: String?
    /** X.509 Certificate SHA-256 Thumbprint parameter */
    val x509CertificateSha256Thumbprint: String?
    /** Critical parameter - identifies which extensions are critical */
    val critical: List<String>?
    /** Additional header parameters */
    val additionalParameters: Map<String, JsonElement>
}