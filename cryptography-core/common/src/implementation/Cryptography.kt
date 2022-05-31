package dev.whyoleg.cryptography.implementation

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithm.*
import dev.whyoleg.cryptography.function.*
import dev.whyoleg.cryptography.implementation.aes.*
import dev.whyoleg.cryptography.implementation.rsa.*
import dev.whyoleg.cryptography.implementation.sha.*

public object Cryptography {
    public val AES: Aes.Companion get() = Aes
    public val RSA: Rsa.Companion get() = Rsa
    public val SHA: Sha.Companion get() = Sha
    public val SHAKE: Shake.Companion get() = Shake
}

private fun <R> resolve(algorithm: CryptographyAlgorithm<R>): R = TODO()

private suspend fun test() {
    resolve(Cryptography.SHA.SHA256).hash {
        update("Hello, world!".encodeToByteArray().view())
        update("!".encodeToByteArray().view())
        val output = ByteArray(outputSize.bytes)
        complete(BufferView.Empty, output.view())
        output
    }

    resolve(Cryptography.SHAKE.SHAKE128).hash(Shake.DigestSize(16.bytes)) {

    }

    val aes = resolve(Cryptography.AES.GCM.NoPadding)

    aes.generate(Unit).apply {
        val key = ByteArray(keySize.bytes).view()
        export(key, Unit)

        encrypt.parameterized {
            val oSize = outputSize(keySize)
            val iv = init()
            update(key, key)
            complete(key, key)
        }

        aes.import(key, Unit).run {
            decrypt {
                outputSize(keySize)
                update(key, key)
                complete(key, key)
            }
        }
    }

    val rsa = resolve(Cryptography.RSA.OAEP)
        .generate(Unit)

    rsa.export()
    rsa.publicKey.export()
    rsa.privateKey.export()

    rsa.publicKey.encrypt {

    }

    rsa.privateKey.decrypt {

    }

}
