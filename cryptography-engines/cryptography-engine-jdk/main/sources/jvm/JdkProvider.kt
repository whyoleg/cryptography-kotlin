package dev.whyoleg.cryptography.jdk

import java.security.*
import javax.crypto.*

public sealed class JdkProvider {
    public object Default : JdkProvider()
    public class Instance(public val provider: Provider) : JdkProvider()
    public class Name(public val provider: String) : JdkProvider()

    internal inline fun <T> get(
        algorithm: String,
        s: (String) -> T,
        s1: (String, String) -> T,
        s2: (String, Provider) -> T,
    ): T = when (this) {
        Default     -> s(algorithm)
        is Name     -> s1(algorithm, provider)
        is Instance -> s2(algorithm, provider)
    }
}

internal fun JdkProvider.cipher(algorithm: String): Cipher =
    get(algorithm, Cipher::getInstance, Cipher::getInstance, Cipher::getInstance)

internal fun JdkProvider.messageDigest(algorithm: String): MessageDigest =
    get(algorithm, MessageDigest::getInstance, MessageDigest::getInstance, MessageDigest::getInstance)

internal fun JdkProvider.mac(algorithm: String): Mac =
    get(algorithm, Mac::getInstance, Mac::getInstance, Mac::getInstance)

internal fun JdkProvider.keyGenerator(algorithm: String): KeyGenerator =
    get(algorithm, KeyGenerator::getInstance, KeyGenerator::getInstance, KeyGenerator::getInstance)
