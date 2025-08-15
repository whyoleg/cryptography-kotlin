/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

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

private fun test(alg: JwaAlgorithm) {
    when (alg) {
        is JweAlgorithm -> TODO()
        is JweEncryptionAlgorithm -> TODO()
        is JwsAlgorithm -> TODO()
        else -> TODO()
    }
}

@OptIn(DelicateJoseApi::class)
private suspend fun test(obj: JwsObject) {
    val header = JwsHeaders(JwsAlgorithm.HS256) {
        protected.apply {
            type = "jwt"
            encodeField("custom", String.serializer(), "value")
            criticalFields("custom")
        }
        unprotected.contentType = "application/json"
    }
    val token = JwtClaims {
        issuer = "test-issuer"
    }

    val header2 = JwsHeader(JwsAlgorithm.HS256) {
        type = "JWT"
        encodeField("custom", String.serializer(), "value")
        criticalFields("custom")
    }
    val claims2 = JwtClaims {
        issuer = "test-issuer"
    }
    val payload2 = Json.JoseCompliant.encodeToString(claims2).encodeToByteArray()
    val content2 = JwsContent(header2, payload2)
    val object2 = content2.sign { _, si -> si }
    val TOKEN = object2.toCompactString()

    val object2A = JwsObject.parseCompactString(TOKEN)
    val content2A = object2.verify { header, signingInput, signature -> true }
    val token2A = Json.JoseCompliant.decodeFromString<JwtClaims>(content2A.payload.decodeToString())
    val issuer2a = token2A.issuer
    val aaa = content2A.header.algorithm


    JwsContent(
        listOf(
            JwsHeaders {

            }
        ),
        JwtClaims {

        }.toJsonString().encodeToByteArray()
    ).sign {

    }.toJsonString()

    JwkObject(
        parameters = JwkParameters.RSA(
            modulus = byteArrayOf(),
            exponent = byteArrayOf(),
            null
        ),
        keyId = "test-key-id",
        publicKeyUse = JwkPublicKeyUse.Signature,
        keyOperations = listOf(JwkOperation.Sign),
        algorithm = null // ???
    )

    Json.JoseCompliant.decodeFromString<JwkObject>("")

    JwsObject.parseCompactString("")
        .verify { _, _, _ -> }
        .payload


    JwsContent(payload2, header)
    JwsContent(payload2, listOf(header))

    JwsObject.parseCompactString()
    JwsObject.parseJsonString()

    val jwsxx = JwsObject.sign("".encodeToByteArray(), header.combined, ::sign)

    JwsObject.sign("".encodeToByteArray(), JwsHeader {

    }) { header, signingInput ->
        signingInput
    }.verify { header, signingInput, signature ->
    }

    JwsObject.sign(
        payload = "".encodeToByteArray(),
        headers = listOf(
            JwsHeaders {

            },
            JwsHeaders {

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

    JwtClaims {
        encode(parsed.payloads.single().header.toJsonObject())
        fromJsonObject()
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
            JwsHeaders {
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

private fun test() {
//    Json(Json.JoseCompliant) {
//        serializersModule = SerializersModule {
//            contextual(JwaAlgorithm::class, JwaAlgorithmSerializer)
//            contextual(JwkParameters::class, TODO())
//        }
//    }


    JwkObject.decodeFromString("").encodeToString()

    jwkRsaKey(

    )



    jwkRsaParameters()
    jwkObject(
        //use, operations, kid, etc
        JwkParameters.rsa()
        // rsaParameters(modulus, exponent)
    )

    JsonWebKey.RSA(
        modulus = byteArrayOf(),
        exponent = byteArrayOf(),
        JsonWebKey.Use.Signature,
        listof(JsonWebKey.Operation.Sign),
        ""
    )

    JsonWebKey(
        JsonWebKey.Parameters.RSA(
            modulus = byteArrayOf(),
            exponent = byteArrayOf()
        ),
        JsonWebKey.Use.Signature,
        listof(JsonWebKey.Operation.Sign),
        ""
    )

    JwkObject(
        parameters = JwkParameters.RSA(
            modulus = byteArrayOf(),
            exponent = byteArrayOf(),
            null
        ),
        keyId = "test-key-id",
        publicKeyUse = JwkPublicKeyUse.Signature,
        keyOperations = listOf(JwkOperation.Sign),
        algorithm = null // ???
    )
}