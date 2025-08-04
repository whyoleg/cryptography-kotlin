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

private fun sign(header: JwsHeader, signingInput: ByteArray): ByteArray = TODO()
private suspend fun sign2(header: JwsHeader, signingInput: ByteArray): ByteArray = TODO()

@OptIn(DelicateJoseApi::class)
private suspend fun test(obj: JwsObject) {
    val header = jwsHeaders(JwsAlgorithm.HS256) {
        protected.apply {
            type = "jwt"
            setCritical("custom", String.serializer(), "value")
        }
        unprotected.contentType = "application/json"
    }
    val token = jwtClaims {
        issuer = "test-issuer"
    }

    jwsContent(
        jwsHeader(JwsHeader.Algorithm.HS256) {
            type = JoseHeader.Type.JWT
            putCritical("custom", String.serializer(), "value")
        },
        jwtClaims {
            issuer = "test-issuer"
        }.toJsonString().encodeToByteArray()
    ).sign { _, si ->
        si
    }.toCompactString()

    jwsContent(
        listOf(
            jwsHeaders {

            }
        ),
        jwtClaims {

        }.toJsonString().encodeToByteArray()
    ).sign {

    }.toJsonString()

    JwsObject.parseCompactString("")
        .verify { _, _, _ -> }
        .payload


    jwsContent(payload, header)
    jwsContent(payload, listOf(header))

    JwsObject.parseCompactString()
    JwsObject.parseJsonString()

    val jwsxx = JwsObject.sign("".encodeToByteArray(), header.combined, ::sign)

    JwsObject.sign("".encodeToByteArray(), jwsHeader {

    }) { header, signingInput ->
        signingInput
    }.verify { header, signingInput, signature ->
    }

    JwsObject.sign(
        payload = "".encodeToByteArray(),
        headers = listOf(
            jwsHeaders {

            },
            jwsHeaders {

            },
        )
    ) { header, signingInput ->

    }

    jwsxx.header.contentType
    jwsxx.header.merged.contentType

    val jwt = JwsObject.sign(
        token.toJsonString().encodeToByteArray(),
        header,
    ) { header, signingInput ->
        signingInput
    }

    val string = jwt.toCompactString()
    val parsed = JwsObject.parseCompactString(string) { header, payload, signature ->
        error("?")
    }

    jwtClaims {
        fromJsonObject(parsed.payloads.single().header.toJsonObject())
        fromJsonString(parsed.payload.decodeToString())
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
            jwsHeaders {
                fromHeaders(header)
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
    val c2 = JsonWebTokenClaims.fromHeader(obj.payloads.single().header)


    Json.JoseCompliant.decodeFromString<JsonObject>(obj.payload.decodeToString())

    buildJsonObject { }
    JwsObject.Header.fromFields(
        JwsObject.Algorithm.HS256
    )

    JwsObject.create(
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
