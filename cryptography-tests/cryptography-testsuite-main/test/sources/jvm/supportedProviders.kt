package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.provider.*
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import kotlin.io.path.*
import kotlin.random.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.JDK
)

//private val SECP256R1 = ECKeyValue.initializeCurve(
//    "secp256r1 [NIST P-256, X9.62 prime256v1]",
//    "1.2.840.10045.3.1.7",
//    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
//    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
//    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
//    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
//    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
//    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
//    1
//)
fun main() {
    val kp = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    (kp.private as ECPrivateKey).params.curve.print()
    (kp.public as ECPublicKey).params.curve.print()

    val factory = KeyFactory.getInstance("EC")


    println(
        AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECGenParameterSpec::class.java).name
    )
    println(
        AlgorithmParameters.getInstance("EC").apply {
            init((kp.public as ECPublicKey).params)
        }.getParameterSpec(ECGenParameterSpec::class.java).name
    )
    println(
        AlgorithmParameters.getInstance("EC").apply {
            init((factory.generatePublic(X509EncodedKeySpec(kp.public.encoded)) as ECPublicKey).params)
        }.getParameterSpec(ECGenParameterSpec::class.java).name
    )


}

private fun EllipticCurve.print() {
    println("$a - $b")
}

fun main2() {
    val file = createTempFile()

    val array1 = Random.nextBytes(50)
    val array2 = Random.nextBytes(100)

    val arrays = listOf(
        array1,
        array2
    )

    file.toFile().outputStream().use { stream ->
        arrays.forEach {
            stream.write(it.size.toByteArray())
            stream.write(it)
        }
    }

    val list = file.toFile().inputStream().use { stream ->
        buildList {
            while (true) {
                val sizeBytes = stream.readNBytes(4)
                if (sizeBytes.isEmpty()) break

                val size = sizeBytes.toInt()
                add(stream.readNBytes(size))
            }
        }
    }

    arrays.zip(list).forEach {
        println(it.first.contentEquals(it.second))
    }
}

fun Int.toByteArray(): ByteArray = byteArrayOf(
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    this.toByte()
)

fun ByteArray.toInt(): Int = (this[0].toInt() shl 24) or (this[1].toInt() shl 16) or (this[2].toInt() shl 8) or this[3].toInt()
