/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

// NIST SHAKE256 examples and CAVP byte-oriented test vectors.
// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
abstract class Shake256TestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<XOF>(SHAKE256, provider) {
    // SHAKE256_Msg0.pdf
    @Test
    fun nistExampleEmptyInput() = testWithAlgorithm {
        algorithm.assertVector(
            input = ByteArray(0),
            expectedHex = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762" +
                    "fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        )
    }

    // SHAKE256_Msg1600.pdf
    @Test
    fun nistExample1600BitInput() = testWithAlgorithm {
        algorithm.assertVector(
            input = ByteArray(200) { 0xa3.toByte() },
            expectedHex = "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d" +
                    "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b",
        )
    }

    // SHAKE256ShortMsg.rsp, Len = 1088
    @Test
    fun nistCavpInputAtRateBoundary() = testWithAlgorithm {
        algorithm.assertVector(
            input = ("d8f12b97f81d47aebbfb7314ff04172cf2be71c3778e238bcccdeecb691fbd54" +
                    "2b00e5b7b1a0abb507f107f781fea700ea7e375fdea9e029754a0ea62216774b" +
                    "da3c59e8783d022360fe9625621c0d93e27f7bc03632942150716f019d048a75" +
                    "2ccc0f93139c55df0f4aaa066a0550cf22e8c54e47d0475ba56b9842a392ffb" +
                    "c6bd98f1e4b64abd1").hexToByteArray(),
            expectedHex = "e2e1c432dd07c2ee89a78f31211c92eeb5306c4fa4db93c4e5cd43080d6079e4",
        )
    }

    // SHAKE256ShortMsg.rsp, Len = 1080
    @Test
    fun nistCavpInputBelowRateBoundary() = testWithAlgorithm {
        algorithm.assertVector(
            input = ("362f1eb00b37a9613b1ae82b90452579d42f8b1f9ede95f86badc6cdf04c9b79" +
                    "af08be4bc94d7cac136979026b92a2d44d2b642ea1431b47d75fce61367919f1" +
                    "71486a007cc271d19de0d1c4c6a11c7a2251fe3aee0bb8938a7dd043d0eb075" +
                    "8a4768c95cc9f6f1703075839487879b47c29c10b2c3e5326ac8f363c65aa4e" +
                    "f76f1b8bd363eb60").hexToByteArray(),
            expectedHex = "c6ce60c1852ea780ed845aac4ca6a30e09f5c0064c9675865178717cfeb1dc97",
        )
    }

    // SHAKE256VariableOut.rsp, COUNT = 0, Outputlen = 16
    @Test
    fun nistCavpMinimumOutput() = testWithAlgorithm {
        algorithm.assertVector(
            input = "c61a9188812ae73994bc0d6d4021e31bf124dc72669749111232da7ac29e61c4".hexToByteArray(),
            expectedHex = "23ce",
        )
    }

    // SHAKE256VariableOut.rsp, COUNT = 1240, Outputlen = 2000
    @Test
    fun nistCavpMaximumOutput() = testWithAlgorithm {
        algorithm.assertVector(
            input = "dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0".hexToByteArray(),
            expectedHex = "00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b" +
                    "41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4cce" +
                    "f6192bbf3a54af18e57b0c146101f6aeaa822bc4b4c9708b09f0b3bab41bcce964d999d1107bd7c27af989ebe1e104a3" +
                    "5478df362ec4c9628f5ea29cc1164b92960d42068a59b1ddcb8875722ed59df36ea654d97b6bf39e5075121ec93f8a8e" +
                    "a6ee5d923997ae8a9d4c315a3d074e3ff83dfa26490f0f5b00a3cc3f110f0f761eaac885a3d1eee302014191733bf77b" +
                    "4d58cca49258897d6460",
        )
    }

    private suspend fun XOF.assertVector(input: ByteArray, expectedHex: String) {
        assertEquals(
            expectedHex,
            hasher((expectedHex.length / 2).bytes).hash(input).toHexString(),
        )
    }
}
