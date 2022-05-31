package dev.whyoleg.cryptography.hm.algorithm.hash

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.cryptography.hm.algorithm.hash.hmac.*
import dev.whyoleg.cryptography.hm.algorithm.hash.sha.*
import dev.whyoleg.cryptography.hm.hash.*
import dev.whyoleg.cryptography.hm.mac.*
import dev.whyoleg.vio.*

//hash vs digest
//TODO: name?
public interface HashAlgorithm<P> : CryptographyAlgorithm {
    public val hash: HashPrimitive<P>
    public val hmacKey: HmacKeyFactory<P>
}

private suspend fun test(provider: CryptographyAlgorithmProvider) {
    val sha = provider.get(Sha.SHA1)

    sha.hash {

    }

    val result = sha.hash(ByteArray(0).view())

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
