/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.json.*

// "iss" Issuer claim (String)

public class JsonWebTokenClaim

public class JsonWebTokenClaimSet(
    public val claims: List<JsonWebTokenClaim>,
)

// we should be able to decode both payload and header into claims?
public class JsonWebTokenClaims private constructor(
    private val obj: JsonObject,
) {
    public val issuer: String?
        get() = obj["issuer"]?.jsonPrimitive?.content

    public companion object {
        public fun fromHeader(header: JoseHeader): JsonWebTokenClaims = TODO()
        public fun fromJsonObject(obj: JsonObject): JsonWebTokenClaims = TODO()
        public fun fromJsonString(string: String): JsonWebTokenClaims = TODO()
    }
}

// JsonWebSignature  / JwsObject (JsonWebSignatureObject)
// JsonWebEncryption / JweObject (JsonWebEncryptionObject)
// JsonWebToken (not a real object)
// JsonWebTokenClaim / JwtClaim
// JsonWebKey
