package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.hash.*

public val SHA1: ShaAlgorithm<Sha1Parameters> = ShaAlgorithm(Sha1Parameters)
public val SHA256: Sha.Algorithm = Sha.Algorithm()
public val SHA512: Sha.Algorithm = Sha.Algorithm()
public val SHA3_256: Sha.Algorithm = Sha.Algorithm()
public val SHA3_512: Sha.Algorithm = Sha.Algorithm()

public interface Sha : HashPrimitive

public class ShaAlgorithm<Parameters>(private val parameters: Parameters) :
    CryptographyAlgorithm<Sha>,
    CryptographyAlgorithm.ForCreate<Sha, Parameters, Parameters>
        where Parameters : ShaParameters, Parameters : CryptographyParametersBuilder<Parameters> {
    override fun builderForCreate(): Parameters = parameters
}

public sealed interface ShaParameters : HashParameters
public object Sha1Parameters : ShaParameters, CryptographyParametersBuilder<Sha1Parameters> {
    override fun build(): Sha1Parameters = this
}

private fun s() {
    val parameters = SHA1.forCreate()
}
