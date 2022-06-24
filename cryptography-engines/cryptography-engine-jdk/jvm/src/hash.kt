package dev.whyoleg.cryptography.engine.jdk

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*
import java.security.*

public class JdkHasher(
    algorithm: String
) : SyncHasher, AsyncHasher, StreamHasher {
    private val md = threadLocal { MessageDigest.getInstance(algorithm) }
    override val digestSize: BinarySize get() = md.get().digestLength.bytes

    override fun hash(input: BufferView): Digest {
        val md = md.get()
        md.reset()
        input.read { md.update(it) }
        return Digest(md.digest().view())
    }

    override fun hash(input: BufferView, digestOutput: Digest): Digest {
        val md = md.get()
        md.reset()
        input.read { md.update(it) }
        digestOutput.value.write { it.put(md.digest()) }
        return digestOutput
    }

    override suspend fun hashAsync(input: BufferView): Digest = hash(input)

    override suspend fun hashAsync(input: BufferView, digestOutput: Digest): Digest = hash(input, digestOutput)

    override fun createHashFunction(): HashFunction {
        TODO("Not yet implemented")
    }
}
