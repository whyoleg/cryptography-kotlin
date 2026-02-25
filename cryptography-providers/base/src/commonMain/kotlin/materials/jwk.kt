/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.materials

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import kotlinx.serialization.json.*
import kotlin.io.encoding.*

@CryptographyProviderApi
public object JsonWebKeys {

    // === Symmetric Keys (AES) ===

    public fun encodeSymmetricKey(algorithmId: CryptographyAlgorithmId<*>, rawKey: ByteArray): ByteArray =
        encodeOctKey(symmetricKeyJwkAlgorithm(algorithmId, rawKey.size), rawKey)

    public fun decodeSymmetricKey(algorithmId: CryptographyAlgorithmId<*>, jwkKey: ByteArray): ByteArray =
        decodeOctKey(jwkKey, symmetricKeyJwkAlgorithm(algorithmId, null))

    // only GCM, CBC, CTR are supported
    private fun symmetricKeyJwkAlgorithm(algorithmId: CryptographyAlgorithmId<*>, keySizeBytes: Int?): String? {
        val mode = when (algorithmId) {
            AES.GCM -> "GCM"
            AES.CBC -> "CBC"
            AES.CTR -> "CTR"
            else    -> return null
        }
        if (keySizeBytes == null) return null
        return when (keySizeBytes) {
            16   -> "A128"
            24   -> "A192"
            32   -> "A256"
            else -> return null
        } + mode
    }

    // === HMAC Keys ===

    public fun encodeHmacKey(digest: CryptographyAlgorithmId<Digest>, rawKey: ByteArray): ByteArray =
        encodeOctKey(hmacJwkAlgorithm(digest), rawKey)

    public fun decodeHmacKey(digest: CryptographyAlgorithmId<Digest>, jwkKey: ByteArray): ByteArray =
        decodeOctKey(jwkKey, hmacJwkAlgorithm(digest))

    private fun hmacJwkAlgorithm(digest: CryptographyAlgorithmId<Digest>): String? = when (digest) {
        SHA256 -> "HS256"
        SHA384 -> "HS384"
        SHA512 -> "HS512"
        else   -> null
    }

    // === EC - Uncompressed format (0x04|x|y) ===

    public fun encodeEcPublicKey(curve: EC.Curve, orderSize: Int, publicKey: ByteArray): ByteArray {
        return encodeEcKey(curve, orderSize, publicKey, null)
    }

    public fun encodeEcPrivateKey(curve: EC.Curve, orderSize: Int, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        return encodeEcKey(curve, orderSize, publicKey, privateKey)
    }

    public fun decodeEcPublicKey(curve: EC.Curve, orderSize: Int, jwkKey: ByteArray): ByteArray {
        return decodeEcKey(curve, orderSize, jwkKey) { publicKey, _ -> publicKey }
    }

    public fun decodeEcPrivateKey(curve: EC.Curve, orderSize: Int, jwkKey: ByteArray): EcPrivateKeyComponents {
        return decodeEcKey(curve, orderSize, jwkKey) { publicKey, d ->
            EcPrivateKeyComponents(
                publicKey = publicKey,
                privateKey = requireNotNull(d) { "'d' is required for private key" },
            )
        }
    }

    public class EcPrivateKeyComponents(
        public val publicKey: ByteArray,
        public val privateKey: ByteArray,
    )

    private fun encodeEcKey(curve: EC.Curve, orderSize: Int, publicKey: ByteArray, d: ByteArray?): ByteArray {
        check(publicKey[0] == 0x04.toByte()) { "Expected uncompressed public key" }
        val x = publicKey.copyOfRange(1, 1 + orderSize)
        val y = publicKey.copyOfRange(1 + orderSize, 1 + orderSize * 2)
        return jwk(kty = "EC", alg = null) {
            put("crv", curve.name)
            put("x", x)
            put("y", y)
            if (d != null) put("d", d)
        }
    }

    private inline fun <T> decodeEcKey(
        curve: EC.Curve,
        orderSize: Int,
        jwkKey: ByteArray,
        transform: (publicKey: ByteArray, d: ByteArray?) -> T,
    ): T {
        val obj = parseJwkWithCurve(jwkKey, "EC", curve.name)
        val x = requireNotNull(obj.getByteArray("x")) { "'x' is required" }
        val y = requireNotNull(obj.getByteArray("y")) { "'y' is required" }
        val publicKey = ByteArray(orderSize * 2 + 1)
        publicKey[0] = 0x04
        x.copyInto(publicKey, 1)
        y.copyInto(publicKey, 1 + orderSize)
        return transform(publicKey, obj.getByteArray("d"))
    }

    // === OKP (EdDSA, XDH) ===

    public fun encodeOkpPublicKey(curve: String, publicKey: ByteArray): ByteArray = jwk(kty = "OKP", alg = null) {
        put("crv", curve)
        put("x", publicKey)
    }

    public fun decodeOkpPublicKey(curve: String, jwkKey: ByteArray): ByteArray {
        val obj = parseJwkWithCurve(jwkKey, "OKP", curve)
        return requireNotNull(obj.getByteArray("x")) { "'x' is required" }
    }

    public fun encodeOkpPrivateKey(curve: String, publicKey: ByteArray, privateKey: ByteArray): ByteArray = jwk(kty = "OKP", alg = null) {
        put("crv", curve)
        put("x", publicKey)
        put("d", privateKey)
    }

    public fun decodeOkpPrivateKey(curve: String, jwkKey: ByteArray): OkpPrivateKeyComponents {
        val obj = parseJwkWithCurve(jwkKey, "OKP", curve)
        return OkpPrivateKeyComponents(
            publicKey = requireNotNull(obj.getByteArray("x")) { "'x' is required" },
            privateKey = requireNotNull(obj.getByteArray("d")) { "'d' is required for private key" },
        )
    }

    public class OkpPrivateKeyComponents(
        public val publicKey: ByteArray,
        public val privateKey: ByteArray,
    )

    // === RSA ===

    public fun encodeRsaPublicKey(
        algorithmId: CryptographyAlgorithmId<*>,
        digest: CryptographyAlgorithmId<Digest>?,
        n: ByteArray, e: ByteArray,
    ): ByteArray = jwk(kty = "RSA", alg = rsaJwkAlgorithm(algorithmId, digest)) {
        put("n", n)
        put("e", e)
    }

    public fun encodeRsaPrivateKey(
        algorithmId: CryptographyAlgorithmId<*>,
        digest: CryptographyAlgorithmId<Digest>?,
        n: ByteArray, e: ByteArray, d: ByteArray,
        p: ByteArray, q: ByteArray,
        dp: ByteArray, dq: ByteArray, qi: ByteArray,
    ): ByteArray = jwk(kty = "RSA", alg = rsaJwkAlgorithm(algorithmId, digest)) {
        put("n", n)
        put("e", e)
        put("d", d)
        put("p", p)
        put("q", q)
        put("dp", dp)
        put("dq", dq)
        put("qi", qi)
    }

    public fun decodeRsaPublicKey(
        algorithmId: CryptographyAlgorithmId<*>,
        digest: CryptographyAlgorithmId<Digest>?,
        jwkKey: ByteArray,
    ): RsaPublicKeyComponents {
        val obj = parseJwkWithAlgorithm(jwkKey, "RSA", rsaJwkAlgorithm(algorithmId, digest))
        return RsaPublicKeyComponents(
            n = requireNotNull(obj.getByteArray("n")) { "'n' is required" },
            e = requireNotNull(obj.getByteArray("e")) { "'e' is required" },
        )
    }

    public fun decodeRsaPrivateKey(
        algorithmId: CryptographyAlgorithmId<*>,
        digest: CryptographyAlgorithmId<Digest>?,
        jwkKey: ByteArray,
    ): RsaPrivateKeyComponents {
        val obj = parseJwkWithAlgorithm(jwkKey, "RSA", rsaJwkAlgorithm(algorithmId, digest))
        return RsaPrivateKeyComponents(
            n = requireNotNull(obj.getByteArray("n")) { "'n' is required" },
            e = requireNotNull(obj.getByteArray("e")) { "'e' is required" },
            d = requireNotNull(obj.getByteArray("d")) { "'d' is required" },
            p = requireNotNull(obj.getByteArray("p")) { "'p' is required" },
            q = requireNotNull(obj.getByteArray("q")) { "'q' is required" },
            dp = requireNotNull(obj.getByteArray("dp")) { "'dp' is required" },
            dq = requireNotNull(obj.getByteArray("dq")) { "'dq' is required" },
            qi = requireNotNull(obj.getByteArray("qi")) { "'qi' is required" },
        )
    }

    public class RsaPublicKeyComponents(
        public val n: ByteArray,
        public val e: ByteArray,
    )

    public class RsaPrivateKeyComponents(
        public val n: ByteArray,
        public val e: ByteArray,
        public val d: ByteArray,
        public val p: ByteArray,
        public val q: ByteArray,
        public val dp: ByteArray,
        public val dq: ByteArray,
        public val qi: ByteArray,
    )

    // RSA alg computation per RFC 7518
    @OptIn(DelicateCryptographyApi::class)
    private fun rsaJwkAlgorithm(algorithmId: CryptographyAlgorithmId<*>, digest: CryptographyAlgorithmId<Digest>?): String? =
        when (algorithmId) {
            RSA.OAEP  -> when (digest) {
                SHA1   -> "RSA-OAEP"
                SHA256 -> "RSA-OAEP-256"
                SHA384 -> "RSA-OAEP-384"
                SHA512 -> "RSA-OAEP-512"
                else   -> null
            }
            RSA.PSS   -> when (digest) {
                SHA256 -> "PS256"
                SHA384 -> "PS384"
                SHA512 -> "PS512"
                else   -> null
            }
            RSA.PKCS1 -> when (digest) {
                SHA256 -> "RS256"
                SHA384 -> "RS384"
                SHA512 -> "RS512"
                else   -> null
            }
            else      -> null
        }

    // === Internal helpers ===

    private fun parseJwk(jwkKey: ByteArray, expectedKty: String): JsonObject {
        val obj = Json.decodeFromString(JsonObject.serializer(), jwkKey.decodeToString())
        require(obj.getString("kty") == expectedKty) { "'kty' should be '$expectedKty'" }
        return obj
    }

    private fun parseJwkWithCurve(jwkKey: ByteArray, expectedKty: String, expectedCurve: String): JsonObject {
        val obj = parseJwk(jwkKey, expectedKty)
        require(obj.getString("crv") == expectedCurve) { "'crv' should be '$expectedCurve'" }
        return obj
    }

    private fun parseJwkWithAlgorithm(jwkKey: ByteArray, expectedKty: String, expectedAlg: String?): JsonObject {
        val obj = parseJwk(jwkKey, expectedKty)
        if (expectedAlg != null) {
            obj.getString("alg")?.let {
                require(it == expectedAlg) { "Wrong 'alg': expected '$expectedAlg', actual '$it'" }
            }
        }
        return obj
    }

    // Symmetric key helpers

    private fun encodeOctKey(alg: String?, rawKey: ByteArray): ByteArray = jwk(kty = "oct", alg = alg) {
        put("k", rawKey)
    }

    private fun decodeOctKey(jwkKey: ByteArray, expectedAlg: String?): ByteArray {
        val obj = parseJwk(jwkKey, "oct")
        val rawKey = requireNotNull(obj.getByteArray("k")) { "'k' was not found" }
        if (expectedAlg != null) {
            obj.getString("alg")?.let {
                require(it == expectedAlg) { "Wrong 'alg': expected '$expectedAlg', actual '$it'" }
            }
        }
        return rawKey
    }

    // JSON/base64url helpers

    private inline fun jwk(kty: String, alg: String?, builderAction: JsonObjectBuilder.() -> Unit): ByteArray =
        buildJsonObject {
            put("kty", kty)
            if (alg != null) put("alg", alg)
            builderAction()
        }.toString().encodeToByteArray()

    // RFC 7515: base64url encoding without padding
    // accept both padded and unpadded input for interoperability
    private val base64Url = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    private fun JsonObjectBuilder.put(key: String, value: ByteArray?) {
        put(key, value?.let(base64Url::encode))
    }

    private fun JsonObject.getByteArray(key: String): ByteArray? {
        return this[key]?.jsonPrimitive?.contentOrNull?.let(base64Url::decode)
    }

    private fun JsonObject.getString(key: String): String? {
        return this[key]?.jsonPrimitive?.contentOrNull
    }

}
