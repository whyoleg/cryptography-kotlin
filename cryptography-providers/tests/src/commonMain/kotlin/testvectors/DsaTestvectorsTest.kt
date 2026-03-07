/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import kotlinx.coroutines.test.*
import kotlinx.serialization.*
import kotlin.test.*

// See https://www.rfc-editor.org/rfc/rfc6979#appendix-A
abstract class DsaTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<DSA>(DSA, provider) {

    private fun rfc6979TestCase(
        digest: CryptographyAlgorithmId<Digest>,
        message: String,
        dsaParameters: DsaParameters,
        yHex: String,
        rHex: String,
        sHex: String,
    ): TestResult = testWithAlgorithm {
        if (!supportsDsaSignatureDigest(digest)) return@testWithAlgorithm

        val parameters = algorithm.parametersDecoder().decodeFromByteArray(
            DSA.Parameters.Format.DER,
            Der.encodeToByteArray(dsaParameters)
        )

        // DSA public key value is a single INTEGER (y) encoded as DER
        val y = BigInt.fromMagnitude(sign = 1, yHex.hexToByteArray())
        val spki = SubjectPublicKeyInfo(
            DsaAlgorithmIdentifier(dsaParameters),
            BitArray(0, Der.encodeToByteArray(BigInt.serializer(), y))
        )
        val publicKey = algorithm.publicKeyDecoder().decodeFromByteArray(
            DSA.PublicKey.Format.DER,
            Der.encodeToByteArray(spki)
        )

        val signature = Der.encodeToByteArray(
            DssSignatureValue.serializer(),
            DssSignatureValue(
                r = BigInt.fromMagnitude(1, rHex.hexToByteArray()),
                s = BigInt.fromMagnitude(1, sHex.hexToByteArray()),
            )
        )
        val data = message.encodeToByteArray()

        // Verify the RFC 6979 known signature
        val verifier = publicKey.signatureVerifier(digest, DSA.SignatureFormat.DER)
        verifier.assertVerifySignature(
            data = data,
            signature = signature,
            message = "RFC 6979 signature verification failed"
        )

        // Also verify that a freshly generated signature is valid
        val keyPair = parameters.keyPairGenerator().generateKey()
        val freshSignature = keyPair.privateKey.signatureGenerator(digest, DSA.SignatureFormat.DER).generateSignature(data)
        val freshVerifier = keyPair.publicKey.signatureVerifier(digest, DSA.SignatureFormat.DER)
        freshVerifier.assertVerifySignature(
            data = data,
            signature = freshSignature,
            message = "Fresh signature verification failed"
        )
    }

    // RFC 6979 Appendix A.2: DSA, 2048 Bits
    // Key parameters
    private val dsa2048p =
        "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48" +
                "C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F" +
                "FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5" +
                "B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2" +
                "35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41" +
                "F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE" +
                "92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15" +
                "3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B"
    private val dsa2048q =
        "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F"
    private val dsa2048g =
        "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613" +
                "D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4" +
                "6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472" +
                "085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5" +
                "AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA" +
                "3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71" +
                "BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0" +
                "DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7"
    private val dsa2048y =
        "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94" +
                "9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61" +
                "1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE" +
                "CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB" +
                "5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254" +
                "687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1" +
                "23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA" +
                "74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF"

    private val dsa2048Parameters = DsaParameters(
        prime = BigInt.fromMagnitude(1, dsa2048p.hexToByteArray()),
        subprime = BigInt.fromMagnitude(1, dsa2048q.hexToByteArray()),
        generator = BigInt.fromMagnitude(1, dsa2048g.hexToByteArray()),
    )

    @Test
    fun rfc6979Dsa2048Sha256Sample() = rfc6979TestCase(
        yHex = dsa2048y,
        dsaParameters = dsa2048Parameters,
        digest = SHA256,
        message = "sample",
        rHex = "EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809",
        sHex = "7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53",
    )

    @Test
    fun rfc6979Dsa2048Sha256Test() = rfc6979TestCase(
        yHex = dsa2048y,
        dsaParameters = dsa2048Parameters,
        digest = SHA256,
        message = "test",
        rHex = "8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0",
        sHex = "7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E",
    )

    @Test
    fun rfc6979Dsa2048Sha384Sample() = rfc6979TestCase(
        yHex = dsa2048y,
        dsaParameters = dsa2048Parameters,
        digest = SHA384,
        message = "sample",
        rHex = "B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B",
        sHex = "19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B",
    )

    @Test
    fun rfc6979Dsa2048Sha512Sample() = rfc6979TestCase(
        yHex = dsa2048y,
        dsaParameters = dsa2048Parameters,
        digest = SHA512,
        message = "sample",
        rHex = "2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E",
        sHex = "D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351",
    )
}
