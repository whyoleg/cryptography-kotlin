package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*

public interface HmacKey : SecretKey {
    public val mac: Mac
}

public class HmacKeyGenerationParameters(
    public val hash: HashParameters
) : SecretKeyGenerationParameters<HmacKey>(KeySize(hash.digestSize.value))
