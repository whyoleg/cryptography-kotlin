/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

typealias DsaParametersTestGroupValidator = EncodableTestGroupValidator<DSA.Parameters.Format, DSA.Parameters, DsaKeyPairTestGroupValidator>
typealias DsaKeyPairTestGroupValidator =
        KeyPairTestGroupValidator<DSA.PublicKey.Format, DSA.PublicKey, DSA.PrivateKey.Format, DSA.PrivateKey, DsaSignatureTestGroupValidator>
typealias DsaSignatureTestGroupValidator = TestGroupValidator<DsaSignatureTestParameters, SignatureTestDataValidator>

@Serializable
data class DsaSignatureTestParameters(
    val digest: SerializableDigest?,
    val format: DSA.SignatureFormat,
) : TestParameters {
    override val id: String get() = "${digest?.name ?: "NONE"}-${format.name}"
}

sealed class DsaTestOperation : TestOperation {
    data class GenerateParameters(val primeSizeBits: Int, val subprimeSizeBits: Int?) : DsaTestOperation()
}

// DSA -> [parameters] -> [key pair] -> [digest, signature format] -> [signature]
abstract class DsaAlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<DSA, DsaParametersTestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = DSA,
    algorithmLimitation = {
        when {
            provider.isWebCrypto || provider.isApple || provider.isCryptoKit -> fails("DSA is not supported")
            else                                                             -> null
        }
    },
) {
    override fun TestValidatorScope.validator(algorithm: DSA): DsaParametersTestGroupValidator = encodables(
        decoder = algorithm.parametersDecoder(),
        formats = { der(DSA.Parameters.Format.DER, DSA.Parameters.Format.PEM, PemLabel.DsaParameters) },
    ) { _ ->
        keyPairs(algorithm.keyPairCodec()) { publicKeys, privateKeys ->
            group<DsaSignatureTestParameters, _>(
                limitation = { (digest) ->
                    when (digest) {
                        // support was added with SHA3 family in https://bugs.openjdk.org/browse/JDK-8252260
                        in setOf(SHA384, SHA512) if provider.isJdkDefault && (platform.isJdk { major < 17 } || platform.isAndroid)
                             -> fails("DSA with SHA384 and SHA512 is not supported on old JDK")
                        // all providers fail when creating signers and verifiers
                        else -> failsIfSignatureDigestUnsupported(digest)
                    }
                },
            ) { (digest, format) ->
                signatures(
                    verifiers = publicKeys.map { it.signatureVerifier(digest, format) },
                    generators = privateKeys.map { it.signatureGenerator(digest, format) },
                    signatureSizes = when (format) {
                        // depends on the subprime size: 160, 224 or 256 bits
                        DSA.SignatureFormat.RAW -> listOf(40, 56, 64)
                        // SEQUENCE of two INTEGERs, each could have leading zero or be shorter
                        DSA.SignatureFormat.DER -> 8..(2 * 32 + 8)
                    },
                    deterministic = false,
                    limitation = { operation ->
                        when (digest) {
                            // `NONEwithDSA` (RawDSA) supports only messages of exactly 20 bytes (SHA-1 digest)
                            null if operation.messageSize != 20 && provider.isJdkDefault
                                 -> fails("DSA without digest supports only messages of exactly 20 bytes")
                            else -> null
                        }
                    },
                )
            }
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        listOf(
            DsaParametersCase(primeSizeBits = 1024, subprimeSizeBits = null, subprimeBits = 160),
            DsaParametersCase(primeSizeBits = 2048, subprimeSizeBits = null, subprimeBits = 224),
            DsaParametersCase(primeSizeBits = 2048, subprimeSizeBits = 256, subprimeBits = 256),
        ).forEach { case ->
            val parameters = operationOrNull(
                operation = DsaTestOperation.GenerateParameters(case.primeSizeBits, case.subprimeSizeBits),
                limitation = { operation ->
                    when {
                        // all providers fail when creating the generator
                        operation.subprimeSizeBits != null && (provider.isBouncyCastle || (provider.isJdkDefault && platform.isAndroid))
                             -> fails("DSAGenParameterSpec is not supported")
                        else -> null
                    }
                },
            ) {
                algorithm.parametersGenerator(case.primeSizeBits.bits, case.subprimeSizeBits?.bits).generateParameters()
            } ?: return@forEach
            encodableGroup(parameters) {
                generateKeyPairGroups(
                    generator = parameters.keyPairGenerator(),
                    iterations = 2,
                    publicKey = DSA.KeyPair::publicKey,
                    privateKey = DSA.KeyPair::privateKey,
                ) { keyPair ->
                    // digest output should be not smaller than the subprime
                    listOf(null, SHA1, SHA256, SHA512, SHA3_256).filter { it == null || it.digestSize * 8 >= case.subprimeBits }
                        .forEach { digest ->
                            DSA.SignatureFormat.entries.forEach { format ->
                                group(DsaSignatureTestParameters(digest, format)) {
                                    generateSignatures(
                                        generator = keyPair.privateKey.signatureGenerator(digest, format),
                                        // without digest, the message is used as a hash, so empty message and message with a single zero byte are equal
                                        messageSizes = when (digest) {
                                            null -> listOf(1, 100, 10000) + List(1) { 1 + CryptographyRandom.nextInt(10000) }
                                            else -> listOf(0, 1, 100, 10000) + List(1) { CryptographyRandom.nextInt(10000) }
                                        },
                                    )
                                }
                            }
                        }
                }
            }
        }
    }

    // https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.2
    @Test
    fun rfc6979() = test("rfc6979") {
        fun bigInt(hex: String): BigInt = BigInt.fromMagnitude(sign = 1, hex.hexToByteArray())

        val dsaParameters = DsaParameters(
            prime = bigInt(
                "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48" +
                        "C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F" +
                        "FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5" +
                        "B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2" +
                        "35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41" +
                        "F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE" +
                        "92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15" +
                        "3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B"
            ),
            subprime = bigInt("F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F"),
            generator = bigInt(
                "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613" +
                        "D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4" +
                        "6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472" +
                        "085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5" +
                        "AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA" +
                        "3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71" +
                        "BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0" +
                        "DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7"
            ),
        )
        val y = bigInt(
            "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94" +
                    "9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61" +
                    "1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE" +
                    "CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB" +
                    "5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254" +
                    "687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1" +
                    "23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA" +
                    "74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF"
        )
        // DSA public key value is a single INTEGER (y)
        val publicKey = SubjectPublicKeyInfo(
            DsaAlgorithmIdentifier(dsaParameters),
            BitArray(0, Der.encodeToByteArray(BigInt.serializer(), y)),
        )

        fun signature(r: String, s: String): ByteString = ByteString(
            Der.encodeToByteArray(DssSignatureValue.serializer(), DssSignatureValue(r = bigInt(r), s = bigInt(s)))
        )

        encodableGroup(
            material(DSA.Parameters.Format.DER, ByteString(Der.encodeToByteArray(DsaParameters.serializer(), dsaParameters))),
            id = "A.2.2",
        ) {
            keyPairGroup(
                publicKey = material(
                    DSA.PublicKey.Format.DER,
                    ByteString(Der.encodeToByteArray(SubjectPublicKeyInfo.serializer(), publicKey))
                ),
                privateKey = null,
            ) {
                group(DsaSignatureTestParameters(SHA256, DSA.SignatureFormat.DER)) {
                    signature(
                        message = text("sample"),
                        signature = signature(
                            r = "EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809",
                            s = "7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53",
                        ),
                    )
                    signature(
                        message = text("test"),
                        signature = signature(
                            r = "8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0",
                            s = "7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E",
                        ),
                    )
                }
                group(DsaSignatureTestParameters(SHA384, DSA.SignatureFormat.DER)) {
                    signature(
                        message = text("sample"),
                        signature = signature(
                            r = "B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B",
                            s = "19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B",
                        ),
                    )
                }
                group(DsaSignatureTestParameters(SHA512, DSA.SignatureFormat.DER)) {
                    signature(
                        message = text("sample"),
                        signature = signature(
                            r = "2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E",
                            s = "D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351",
                        ),
                    )
                }
            }
        }
    }
}

private class DsaParametersCase(
    val primeSizeBits: Int,
    val subprimeSizeBits: Int?,
    // actual size of the subprime
    val subprimeBits: Int,
)

private fun DSA.keyPairCodec(): KeyPairTestCodec<DSA.PublicKey.Format, DSA.PublicKey, DSA.PrivateKey.Format, DSA.PrivateKey> =
    keyPairCodec(
        publicKey = encodableCodec(publicKeyDecoder()) {
            der(DSA.PublicKey.Format.DER, DSA.PublicKey.Format.PEM, PemLabel.PublicKey)
        },
        privateKey = encodableCodec(privateKeyDecoder()) {
            der(DSA.PrivateKey.Format.DER, DSA.PrivateKey.Format.PEM, PemLabel.PrivateKey)
        },
        getPublicKey = { it.getPublicKey() },
    )
