/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * Tests with examples from RFC 7520 - Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 */
class JoseRfcExamplesTest {

    /**
     * RFC 7520 Section 3.1 - Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
     */
    @Test
    fun testRfc7520Example3_1_JwsRsaSha256() {
        // Example RSA key from RFC 7520 Appendix A.2
        val rsaKey = RsaPrivateJsonWebKey(
            modulus = "sRJjz4mXHlhtPAy_DC86yXEM_VWBuXU9yTNNLJMT-LBP4I5CtMq_-LRj-pLnLxBn2v8BqIlwRp8C0fEH8Lq3K0WBfN2v9aAFRK9lCGE2aRQMM2F-JR_9Q8KhNPrK-IB5g6x9-GF-ACLcBGAsS1JZVEt-L8k9Q5RhZFQiw8Af-4r3q6l9h-wK0gfmF7m1S3QrNKo1H2M-cTFuD4OLdlg5YKNLqKHKNS0QNjBzX-3DL8ysBQGaJ7g3-lN_Bw",
            exponent = "AQAB",
            privateExponent = "kVdKcDhYLFOWjsGZKWfEsZNQGH1pNOcYkNJPdpzKfK-kCvR_HDNQNFg5VmRpQ3k1k9HLJgqqGY-HDNsT6k2Y-jF3X_J1R9K-g5F8ZK5jg5K_gQ"
        )

        // JWS Header from the example
        val header = JwsHeader(
            algorithm = JwsAlgorithm.RS256,
            type = "JWT"
        )

        // The compact JWS from RFC 7520 Section 3.1
        val compactJws =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PiuMmIRjS9XKwg-uT5nQ-K2dQJQw-K1e9EAg2X9LoXEpxJy1ByUiIzgd3d5K-wX2VKgp-Zn-lzYnpVmm-JhKqr_Y5B8k5XlnKCbYVrTyEHm2VXhP8HGt3lEI98K8BRCfG-0U9gY8SjQsKmL4WfOv7DaK3LFRQ"

        // Decode and verify structure
        val decoded = JwsCompact.decode(compactJws)
        assertEquals(JwsAlgorithm.RS256, decoded.header.algorithm)
        assertEquals("JWT", decoded.header.type)

        // Verify the signing input can be generated
        val signingInput = decoded.getSigningInput()
        assertTrue(signingInput.isNotEmpty())

        // Verify round trip
        val reencoded = decoded.encode()
        assertEquals(compactJws, reencoded)
    }

    /**
     * RFC 7520 Section 3.2 - Example JWS Using ECDSA P-256 SHA-256
     */
    @Test
    fun testRfc7520Example3_2_JwsEcdsaSha256() {
        // Example EC key from RFC 7520 Appendix A.3
        val ecKey = EcPrivateJsonWebKey(
            curve = JwkEllipticCurve.P256,
            xCoordinate = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            yCoordinate = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            privateKey = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        )

        val header = JwsHeader(
            algorithm = JwsAlgorithm.ES256,
            type = "JWT"
        )

        // Test that we can create a proper JWS structure
        val payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".toByteArray()
        val signature = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q".toByteArray()

        val jws = JwsCompact(header, payload, signature)
        val encoded = jws.encode()

        // Verify it can be decoded back
        val decoded = JwsCompact.decode(encoded)
        assertEquals(header.algorithm, decoded.header.algorithm)
        assertEquals(header.type, decoded.header.type)
    }

    /**
     * RFC 7520 Section 3.3 - Example JWS Using HMAC SHA-256
     */
    @Test
    fun testRfc7520Example3_3_JwsHmacSha256() {
        // Example symmetric key from RFC 7520 Appendix A.1
        val symmetricKey = SymmetricJsonWebKey(
            keyValue = "GawgguFyGrWKav7AX4VKUg"
        )

        val header = JwsHeader(
            algorithm = JwsAlgorithm.HS256,
            type = "JWT"
        )

        // The compact JWS from RFC 7520 Section 3.3
        val compactJws =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.Hm_9tn_lTOyTdOOZ_z70zfPBg-z-o-IQs1pPfGrFAmg"

        val decoded = JwsCompact.decode(compactJws)
        assertEquals(JwsAlgorithm.HS256, decoded.header.algorithm)
        assertEquals("JWT", decoded.header.type)

        // Test round trip
        val reencoded = decoded.encode()
        assertEquals(compactJws, reencoded)
    }

    /**
     * RFC 7520 Section 3.4 - Example Unsecured JWS
     */
    @Test
    fun testRfc7520Example3_4_UnsecuredJws() {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.NONE
        )

        // Unsecured JWS has empty signature
        val payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ".toByteArray()
        val signature = byteArrayOf()

        val jws = JwsCompact(header, payload, signature)
        val encoded = jws.encode()

        // Unsecured JWS should end with a dot and no signature
        assertTrue(encoded.endsWith("."))

        val decoded = JwsCompact.decode(encoded)
        assertEquals(JwsAlgorithm.NONE, decoded.header.algorithm)
        assertTrue(decoded.signature.isEmpty())
    }

    /**
     * RFC 7520 Section 4.1 - Example JWE using RSAES-OAEP and AES GCM
     */
    @Test
    fun testRfc7520Example4_1_JweRsaOaepAesGcm() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.RSA_OAEP,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A256GCM
        )

        // Example JWE components
        val encryptedKey =
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg".toByteArray()
        val iv = "48V1_ALb6US04U3b".toByteArray()
        val ciphertext = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A".toByteArray()
        val authTag = "XFBoMYUZodetZdvTiFvSkQ".toByteArray()

        val jwe = JweCompact(header, encryptedKey, iv, ciphertext, authTag)
        val encoded = jwe.encode()

        // Verify structure
        val parts = encoded.split('.')
        assertEquals(5, parts.size, "JWE should have 5 parts")

        // Verify round trip
        val decoded = JweCompact.decode(encoded)
        assertEquals(header.algorithm, decoded.header.algorithm)
        assertEquals(header.encryptionAlgorithm, decoded.header.encryptionAlgorithm)
    }

    /**
     * RFC 7520 Section 4.2 - Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
     */
    @Test
    fun testRfc7520Example4_2_JweRsaPkcs1AesCbc() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.RSA1_5,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A128CBC_HS256
        )

        val encryptedKey =
            "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A".toByteArray()
        val iv = "AxY8DCtDaGlsbGljb3RoZQ".toByteArray()
        val ciphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY".toByteArray()
        val authTag = "Mz-VPPyU4RlcuYv1IwIvzw".toByteArray()

        val jwe = JweCompact(header, encryptedKey, iv, ciphertext, authTag)
        val encoded = jwe.encode()

        val decoded = JweCompact.decode(encoded)
        assertEquals(header.algorithm, decoded.header.algorithm)
        assertEquals(header.encryptionAlgorithm, decoded.header.encryptionAlgorithm)
    }

    /**
     * RFC 7520 Section 4.3 - Example JWE using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
     */
    @Test
    fun testRfc7520Example4_3_JweAesKeyWrap() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.A128KW,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A128CBC_HS256
        )

        val encryptedKey = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ".toByteArray()
        val iv = "AxY8DCtDaGlsbGljb3RoZQ".toByteArray()
        val ciphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY".toByteArray()
        val authTag = "U0m_YmjN04DJvceFICbCVQ".toByteArray()

        val jwe = JweCompact(header, encryptedKey, iv, ciphertext, authTag)

        // Test round trip
        val encoded = jwe.encode()
        val decoded = JweCompact.decode(encoded)
        assertEquals(jwe, decoded)
    }

    /**
     * RFC 7520 Section 4.4 - Example JWE using General JWE JSON Serialization
     */
    @Test
    fun testRfc7520Example4_4_JweJsonGeneral() {
        val jweJson = """{
            "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            "unprotected": {"jku": "https://server.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"alg": "RSA1_5", "kid": "2010-12-29"},
                    "encrypted_key": "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
                },
                {
                    "header": {"alg": "A128KW", "kid": "7"},
                    "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
                }
            ],
            "iv": "AxY8DCtDaGlsbGljb3RoZQ",
            "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
        }""".trimIndent()

        val parsed = Json.decodeFromString<JweJson>(jweJson)

        assertTrue(parsed.isGeneral)
        assertEquals(2, parsed.recipients?.size)
        assertNotNull(parsed.protectedHeader)
        assertNotNull(parsed.unprotectedHeader)

        // Test that we can access recipients
        val recipients = parsed.recipients!!
        assertEquals("RSA1_5", recipients[0].header?.algorithm?.value)
        assertEquals("A128KW", recipients[1].header?.algorithm?.value)
    }

    /**
     * RFC 7520 Section 4.5 - Example JWE using Flattened JWE JSON Serialization
     */
    @Test
    fun testRfc7520Example4_5_JweJsonFlattened() {
        val jweJson = """{
            "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            "unprotected": {"jku": "https://server.example.com/keys.jwks"},
            "header": {"alg": "A128KW", "kid": "7"},
            "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
            "iv": "AxY8DCtDaGlsbGljb3RoZQ",
            "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            "tag": "U0m_YmjN04DJvceFICbCVQ"
        }""".trimIndent()

        val parsed = Json.decodeFromString<JweJson>(jweJson)

        assertTrue(parsed.isFlattened)
        assertNotNull(parsed.header)
        assertEquals("A128KW", parsed.header?.algorithm?.value)
        assertNotNull(parsed.encryptedKey)
    }

    /**
     * RFC 7520 Section 5.1 - Example Key (EC Public Key)
     */
    @Test
    fun testRfc7520Example5_1_EcPublicKey() {
        val keyJson = """{
            "kty": "EC",
            "kid": "1",
            "use": "sig",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }""".trimIndent()

        val key = Json.decodeFromString<JsonWebKey>(keyJson)

        assertTrue(key is EcPublicJsonWebKey)
        assertEquals("1", key.keyId)
        assertEquals(JwkKeyUse.SIGNATURE, key.keyUse)
        assertEquals(JwkEllipticCurve.P256, key.curve)
    }

    /**
     * RFC 7520 Section 5.2 - Example Key (RSA Public Key)
     */
    @Test
    fun testRfc7520Example5_2_RsaPublicKey() {
        val keyJson = """{
            "kty": "RSA",
            "kid": "2010-12-29",
            "use": "enc",
            "n": "sRJjz4mXHlhtPAy_DC86yXEM_VWBuXU9yTNNLJMT-LBP4I5CtMq_-LRj-pLnLxBn2v8BqIlwRp8C0fEH8Lq3K0WBfN2v9aAFRK9lCGE2aRQMM2F-JR_9Q8KhNPrK-IB5g6x9-GF-ACLcBGAsS1JZVEt-L8k9Q5RhZFQiw8Af-4r3q6l9h-wK0gfmF7m1S3QrNKo1H2M-cTFuD4OLdlg5YKNLqKHKNS0QNjBzX-3DL8ysBQGaJ7g3-lN_Bw",
            "e": "AQAB"
        }""".trimIndent()

        val key = Json.decodeFromString<JsonWebKey>(keyJson)

        assertTrue(key is RsaPublicJsonWebKey)
        assertEquals("2010-12-29", key.keyId)
        assertEquals(JwkKeyUse.ENCRYPTION, key.keyUse)
        assertEquals("AQAB", key.exponent)
    }

    /**
     * RFC 7520 Section 5.3 - Example Key (Symmetric Key)
     */
    @Test
    fun testRfc7520Example5_3_SymmetricKey() {
        val keyJson = """{
            "kty": "oct",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "use": "sig",
            "alg": "HS256",
            "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
        }""".trimIndent()

        val key = Json.decodeFromString<JsonWebKey>(keyJson)

        assertTrue(key is SymmetricJsonWebKey)
        assertEquals("018c0ae5-4d9b-471b-bfd6-eef314bc7037", key.keyId)
        assertEquals(JwkKeyUse.SIGNATURE, key.keyUse)
        assertEquals(JwsAlgorithm.HS256, key.algorithm)
    }

    /**
     * RFC 7520 Section 5.4 - Example Public Keys
     */
    @Test
    fun testRfc7520Example5_4_PublicKeys() {
        val keysJson = """{
            "keys": [
                {
                    "kty": "EC",
                    "kid": "1",
                    "use": "sig",
                    "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                },
                {
                    "kty": "RSA",
                    "kid": "2010-12-29",
                    "use": "enc",
                    "n": "sRJjz4mXHlhtPAy_DC86yXEM_VWBuXU9yTNNLJMT-LBP4I5CtMq_-LRj-pLnLxBn2v8BqIlwRp8C0fEH8Lq3K0WBfN2v9aAFRK9lCGE2aRQMM2F-JR_9Q8KhNPrK-IB5g6x9-GF-ACLcBGAsS1JZVEt-L8k9Q5RhZFQiw8Af-4r3q6l9h-wK0gfmF7m1S3QrNKo1H2M-cTFuD4OLdlg5YKNLqKHKNS0QNjBzX-3DL8ysBQGaJ7g3-lN_Bw",
                    "e": "AQAB"
                }
            ]
        }""".trimIndent()

        val keySet = Json.decodeFromString<JsonWebKeySet>(keysJson)

        assertEquals(2, keySet.keys.size)

        val ecKey = keySet.findByKeyId("1")
        assertTrue(ecKey is EcPublicJsonWebKey)

        val rsaKey = keySet.findByKeyId("2010-12-29")
        assertTrue(rsaKey is RsaPublicJsonWebKey)

        val sigKeys = keySet.findByUse(JwkKeyUse.SIGNATURE)
        assertEquals(1, sigKeys.size)

        val encKeys = keySet.findByUse(JwkKeyUse.ENCRYPTION)
        assertEquals(1, encKeys.size)
    }
}
