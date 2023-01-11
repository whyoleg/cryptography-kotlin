package dev.whyoleg.cryptography.testcase.main

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.provider.*
import kotlin.io.path.*
import kotlin.random.*

internal actual val supportedProviders: List<CryptographyProvider> = listOf(
    CryptographyProvider.JDK
)

fun main() {
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
