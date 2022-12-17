package dev.whyoleg.cryptography.algorithms.mac

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.sha.*
import dev.whyoleg.cryptography.hash.*

public interface HMAC {
    public companion object : CryptographyAlgorithm<HMAC>

    public class Parameters<T : HashProvider<HP>, HP : CryptographyParameters>(
        public val algorithm: CryptographyAlgorithm<T>,
        public val parameters: HP,
    )
}

private fun tests(engine: CryptographyEngine) {

    val s = HMAC.Parameters(SHAKE128, SHAKE128.Parameters(256.bytes))

    engine.get(SHAKE128)
}
