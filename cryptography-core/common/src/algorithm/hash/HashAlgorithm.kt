package dev.whyoleg.cryptography.algorithm.hash

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithm.hash.hmac.*
import dev.whyoleg.cryptography.algorithm.hash.sha.*
import dev.whyoleg.cryptography.operation.*
import dev.whyoleg.vio.*

//hash vs digest
//TODO: name?
public interface HashAlgorithm<C, OP, CP> : CryptographyAlgorithm {
    public val hash: HashOperation<C, OP, CP>
    public val hmacKey: HmacKeyFactory<P>
}

private suspend fun test(provider: CryptographyAlgorithmProvider) {
    val sha = provider.get(Sha.SHA1)

    sha.hash.invoke(Unit, Unit).use {

    }

    val result = sha.hash(Unit, ByteArray(0).view())

    sha.hash.async {

    }

    val result2 = sha.hash.async(ByteArray(0).view())
}

private suspend fun test(sha: Sha) {
    sha.hmacKey.async.generate(12.bytes).run {
        val exportedKey = export()

        val result = mac("ByteArray".encodeToByteArray().view())
    }
}
