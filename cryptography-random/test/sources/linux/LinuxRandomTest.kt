package dev.whyoleg.cryptography.random

class URandomTest : CryptographyRandomTest(createURandom())

class GetRandomTest : CryptographyRandomTest(createGetRandom()!!)
