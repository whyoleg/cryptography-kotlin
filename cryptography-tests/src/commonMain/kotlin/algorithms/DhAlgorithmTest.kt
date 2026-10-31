/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import dev.whyoleg.cryptography.testhost.*
import dev.whyoleg.cryptography.tests.*
import dev.whyoleg.cryptography.tests.operations.*
import kotlinx.io.bytestring.*
import kotlin.test.*

typealias DhParametersTestGroupValidator = EncodableTestGroupValidator<DH.Parameters.Format, DH.Parameters, DhKeyAgreementTestGroupValidator>
typealias DhKeyAgreementTestGroupValidator =
        KeyAgreementTestGroupValidator<DH.PublicKey.Format, DH.PublicKey, DH.PrivateKey.Format, DH.PrivateKey, SharedSecretTestDataValidator>

sealed class DhTestOperation : TestOperation {
    data class GenerateParameters(val primeSizeBits: Int, val privateValueSizeBits: Int?) : DhTestOperation()
}

// DH -> [parameters] -> [two key pairs] -> [shared secret]
abstract class DhAlgorithmTest(cryptographyProvider: CryptographyProvider) : AlgorithmTest<DH, DhParametersTestGroupValidator>(
    provider = cryptographyProvider,
    algorithmId = DH,
    algorithmLimitation = {
        when {
            provider.isWebCrypto || provider.isApple || provider.isCryptoKit -> fails("DH is not supported")
            else                                                             -> null
        }
    },
) {
    override fun TestValidatorScope.validator(algorithm: DH): DhParametersTestGroupValidator = encodables(
        decoder = algorithm.parametersDecoder(),
        formats = { der(DH.Parameters.Format.DER, DH.Parameters.Format.PEM, PemLabel.DhParameters, check = ::assertDhParametersEquals) },
    ) { _ ->
        keyAgreements(algorithm.keyPairCodec()) { first, second ->
            sharedSecrets(
                first = first,
                second = second,
                publicKeyGenerator = { it.sharedSecretGenerator() },
                privateKeyGenerator = { it.sharedSecretGenerator() },
                // could depend on the provider: some of them strip leading zeros
                sharedSecretSize = null,
            )
        }
    }

    @Test
    fun random() = test("random") { algorithm ->
        listOf(1024, 2048).forEach { primeSizeBits ->
            listOf(null, 256, 512).forEach { privateValueSizeBits ->
                val parameters = operationOrNull(
                    operation = DhTestOperation.GenerateParameters(primeSizeBits, privateValueSizeBits),
                    limitation = { operation ->
                        when {
                            operation.primeSizeBits <= 1024 -> null
                            provider.isBouncyCastle         -> skip("DH parameter generation is very slow with BouncyCastle")
                            provider.isOpenssl3             -> skip("DH parameter generation is very slow with OpenSSL")
                            platform.isAndroid              -> skip("DH parameter generation is very slow on Android")
                            else                            -> null
                        }
                    },
                ) {
                    algorithm.parametersGenerator(primeSizeBits.bits, privateValueSizeBits?.bits).generateParameters()
                }
                if (parameters != null) parametersGroup(parameters)
            }
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc3526 (MODP groups with generator 2)
    @Test
    fun rfc3526() = test("rfc3526") { algorithm ->
        rfc3526Primes.forEach { (primeSizeBits, prime) ->
            val der = Der.encodeToByteArray(
                DhParameters.serializer(),
                DhParameters(prime = BigInt.fromMagnitude(sign = 1, prime.joinToString("").hexToByteArray()), base = 2.toBigInt()),
            )
            val parameters = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, der)
            parametersGroup(parameters, id = "$primeSizeBits-bit-MODP")
        }
    }
}

context(context: TestGenerationContext)
private suspend fun DhParametersTestGroupValidator.parametersGroup(
    parameters: DH.Parameters,
    id: String = context.generateChildId(),
): Unit = encodableGroup(parameters, id) {
    generateKeyAgreementGroups(
        generator = parameters.keyPairGenerator(),
        iterations = 2,
        publicKey = DH.KeyPair::publicKey,
        privateKey = DH.KeyPair::privateKey,
    ) { first, second ->
        generateSharedSecret(first.privateKey.sharedSecretGenerator(), second.publicKey)
    }
}

private fun DH.keyPairCodec(): KeyPairTestCodec<DH.PublicKey.Format, DH.PublicKey, DH.PrivateKey.Format, DH.PrivateKey> =
    keyPairCodec(
        publicKey = encodableCodec(publicKeyDecoder()) {
            der(DH.PublicKey.Format.DER, DH.PublicKey.Format.PEM, PemLabel.PublicKey, check = ::assertDhSubjectPublicKeyInfoEquals)
        },
        privateKey = encodableCodec(privateKeyDecoder()) {
            der(DH.PrivateKey.Format.DER, DH.PrivateKey.Format.PEM, PemLabel.PrivateKey, check = ::assertDhPrivateKeyInfoEquals)
        },
        getPublicKey = { it.getPublicKey() },
    )

// the optional `privateValueLength` field may not be preserved by all providers
private fun assertDhParametersEquals(expected: DhParameters?, actual: DhParameters?) {
    assertNotNull(expected, "DhParameters (expected)")
    assertNotNull(actual, "DhParameters (actual)")
    assertEquals(expected.prime, actual.prime, "DhParameters.prime")
    assertEquals(expected.base, actual.base, "DhParameters.base")
    if (expected.privateValueLength != null && actual.privateValueLength != null) {
        assertEquals(expected.privateValueLength, actual.privateValueLength, "DhParameters.privateValueLength")
    }
}

private fun assertDhParametersEquals(expected: ByteString, actual: ByteString) = assertDhParametersEquals(
    Der.decodeFromByteArray(DhParameters.serializer(), expected.toByteArray()),
    Der.decodeFromByteArray(DhParameters.serializer(), actual.toByteArray()),
)

private fun assertDhSubjectPublicKeyInfoEquals(expected: ByteString, actual: ByteString) {
    val expectedInfo = Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), expected.toByteArray())
    val actualInfo = Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), actual.toByteArray())
    assertDhParametersEquals(
        assertIs<DhAlgorithmIdentifier>(expectedInfo.algorithm).parameters,
        assertIs<DhAlgorithmIdentifier>(actualInfo.algorithm).parameters,
    )
    assertEquals(
        expectedInfo.subjectPublicKey.unusedBits,
        actualInfo.subjectPublicKey.unusedBits,
        "SubjectPublicKeyInfo.subjectPublicKey.unusedBits"
    )
    assertBytesEquals(ByteString(expectedInfo.subjectPublicKey.byteArray), ByteString(actualInfo.subjectPublicKey.byteArray)) {
        "SubjectPublicKeyInfo.subjectPublicKey"
    }
}

private fun assertDhPrivateKeyInfoEquals(expected: ByteString, actual: ByteString) {
    val expectedInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), expected.toByteArray())
    val actualInfo = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), actual.toByteArray())
    assertDhParametersEquals(
        assertIs<DhAlgorithmIdentifier>(expectedInfo.privateKeyAlgorithm).parameters,
        assertIs<DhAlgorithmIdentifier>(actualInfo.privateKeyAlgorithm).parameters,
    )
    assertBytesEquals(ByteString(expectedInfo.privateKey), ByteString(actualInfo.privateKey)) { "PrivateKeyInfo.privateKey" }
}

// primes of MODP groups by size in bits
private val rfc3526Primes: Map<Int, List<String>> = mapOf(
    // Section 2, Group 5
    1536 to listOf(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    ),
    // Section 3, Group 14
    2048 to listOf(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    ),
    // Section 4, Group 15
    3072 to listOf(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    ),
    // Section 5, Group 16
    4096 to listOf(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA",
        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED",
        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199",
        "FFFFFFFFFFFFFFFF",
    ),
    // Section 6, Group 17
    6144 to listOf(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA",
        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED",
        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492",
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD",
        "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831",
        "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B",
        "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF",
        "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6",
        "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3",
        "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA",
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328",
        "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C",
        "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE",
        "12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
    ),
    // Section 7, Group 18
    8192 to listOf(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA",
        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED",
        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492",
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD",
        "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831",
        "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B",
        "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF",
        "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6",
        "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3",
        "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA",
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328",
        "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C",
        "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE",
        "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4",
        "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300",
        "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568",
        "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9",
        "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B",
        "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A",
        "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36",
        "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1",
        "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92",
        "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47",
        "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71",
        "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
    ),
)
