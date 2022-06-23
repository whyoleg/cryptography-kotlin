package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.digest.*

public typealias ShaDigestAlgorithm = CryptographyPrimitiveAlgorithm<Digest, EmptyMaterial, EmptyParameters>
public typealias ShaDigestDescriptorFactory = CryptographyPrimitiveDescriptorFactory<Digest, EmptyMaterial, EmptyParameters, Unit>
public typealias ShaDigestId<D> = CryptographyPrimitiveId<Digest, D, EmptyMaterial, EmptyParameters>
public typealias ShaDigestFactory<D> = CryptographyPrimitiveFactory<Digest, D, EmptyMaterial, EmptyParameters, Unit>

public val Sha1DigestAlgorithm: ShaDigestAlgorithm get() = ShaDigestAlgorithm("SHAKE128")
public val Sha1DigestDescriptor: ShaDigestDescriptorFactory
    get() = ShaDigestDescriptorFactory(Sha1DigestAlgorithm, EmptyParameters)

public val Sha1DigestId: ShaDigestId<Digest.Sync> get() = ShaDigestId(Sha1DigestAlgorithm, "SYNC")
public val Sha1AsyncDigestId: ShaDigestId<Digest.Async> get() = ShaDigestId(Sha1DigestAlgorithm, "ASYNC")
public val Sha1StreamDigestId: ShaDigestId<Digest.Stream> get() = ShaDigestId(Sha1DigestAlgorithm, "STREAM")

public val Sha1Digest: ShaDigestFactory<Digest.Sync> get() = ShaDigestFactory(Sha1DigestId, EmptyParameters)
public val Sha1AsyncDigest: ShaDigestFactory<Digest.Async> get() = ShaDigestFactory(Sha1AsyncDigestId, EmptyParameters)
public val Sha1StreamDigest: ShaDigestFactory<Digest.Stream> get() = ShaDigestFactory(Sha1StreamDigestId, EmptyParameters)

public val Sha256DigestId: ShaDigestId<Digest.Sync> get() = ShaDigestId("SHA2-256|SYNC")
public val Sha256AsyncDigestId: ShaDigestId<Digest.Async> get() = ShaDigestId("SHA2-256|ASYNC")
public val Sha256StreamDigestId: ShaDigestId<Digest.Stream> get() = ShaDigestId("SHA2-256|STREAM")

public val Sha256Digest: ShaDigestFactory<Digest.Sync> get() = ShaDigestFactory(Sha256DigestId, EmptyParameters)
public val Sha256AsyncDigest: ShaDigestFactory<Digest.Async> get() = ShaDigestFactory(Sha256AsyncDigestId, EmptyParameters)
public val Sha256StreamDigest: ShaDigestFactory<Digest.Stream> get() = ShaDigestFactory(Sha256StreamDigestId, EmptyParameters)

public val Sha3K256DigestId: ShaDigestId<Digest.Sync> get() = ShaDigestId("SHA3-256|SYNC")
public val Sha3K256AsyncDigestId: ShaDigestId<Digest.Async> get() = ShaDigestId("SHA3-256|ASYNC")
public val Sha3K256StreamDigestId: ShaDigestId<Digest.Stream> get() = ShaDigestId("SHA3-256|STREAM")

public val Sha3K256Digest: ShaDigestFactory<Digest.Sync> get() = ShaDigestFactory(Sha3K256DigestId, EmptyParameters)
public val Sha3K256AsyncDigest: ShaDigestFactory<Digest.Async> get() = ShaDigestFactory(Sha3K256AsyncDigestId, EmptyParameters)
public val Sha3K256StreamDigest: ShaDigestFactory<Digest.Stream> get() = ShaDigestFactory(Sha3K256StreamDigestId, EmptyParameters)
