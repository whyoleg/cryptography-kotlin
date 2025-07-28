/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose.v0

import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.json.*
import kotlin.io.encoding.*

public val Json.Default.JoseCompliant: Json by lazy {
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = false // TODO?
    }
}

@RequiresOptIn(
    message = "TODO",
    level = RequiresOptIn.Level.ERROR,
)
public annotation class DelicateJoseApi

internal val Base64Url = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

internal fun parseCompactString(compact: String, expectedParts: Int): List<String> {
    val parts = compact.split('.')
    require(parts.size == expectedParts) {
        "Invalid compact format: expected $expectedParts parts separated by dots, got ${parts.size}"
    }
    return parts
}

@OptIn(DelicateJoseApi::class)
private suspend fun test(obj: JwsObject) {
    val header = jwsObjectHeader(JwsHeader.Algorithm.HS256) {
        protected {
            type = JoseHeader.Type.JWT
            putCritical("custom", String.serializer(), "value")
        }
        unprotected.contentType = JoseHeader.ContentType("application/json")
    }

    if (JoseHeader.Type in header) {
        // do something
    }

    val signer: suspend (JwsHeader, ByteArray) -> ByteArray = { _: JwsHeader, _: ByteArray ->
        "".encodeToByteArray()
    }

    JwsObject.sign("data".encodeToByteArray(), header) { header, signingInput ->
        signer(header, signingInput)
    }

    val jws = JwsObject.sign("data".encodeToByteArray(), header) { header, signingInput ->
        signingInput
    }
    val jwsMulti = JwsObject.sign(
        "data".encodeToByteArray(), listOf(
            header,
            jwsObjectHeader {
                fromObjectHeader(header)
                protected.put("kid", String.serializer(), "test-key")
            },
        )
    ) { header, signingInput ->
        signingInput
    }
    val jws2 = JwsObject.presigned("    ".encodeToByteArray(), header, "xxx".encodeToByteArray())

    JwsObject.parseCompactString("") { header, payload, signature ->
    }
    JwsObject.parseCompactStringUnverified("")

    JwsObject(
        "".encodeToByteArray(),
        JwsHeader {

        },

        ) {

    }
    JwsObject(
        buildJoseHeader {
            from(JWT())
            from(OID4VP(...))
            put(JoseHeaderParameter("test", String.serializer()), "test")
        },
        "".encodeToByteArray()
    ) {
        // sign function
    }

    // JsonWebSignatureObject.build


    val c1 = JsonWebTokenClaims.fromJsonString(obj.payload.decodeToString())
    val c2 = JsonWebTokenClaims.fromHeader(obj.signatures.single().header)


    Json.JoseCompliant.decodeFromString<JsonObject>(obj.payload.decodeToString())

    buildJsonObject { }
    JwsObject.Header.fromFields(
        JwsObject.Algorithm.HS256
    )

    val jwt = JwsObject.create(
        JwsObject.Header.fromFields(null),
        Json.JoseCompliant.encodeToString(
            JwtClaims()
        ).encodeToByteArray()
    ) { x, y ->
        x.algorithm
        y
    }.toCompactString()
//    Uuid.parse("test-uuid-v0")
}
