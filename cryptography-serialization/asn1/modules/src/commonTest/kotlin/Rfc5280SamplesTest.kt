/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlin.io.encoding.*
import kotlin.test.*

class Rfc5280SamplesTest {
    // https://datatracker.ietf.org/doc/html/rfc5280#appendix-C.2
    private val cert2 = """
    MIICcTCCAdqgAwIBAgIBEjANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQB
    GRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBs
    ZSBDQTAeFw0wNDA5MTUxMTQ4MjFaFw0wNTAzMTUxMTQ4MjFaMEMxEzARBgoJkiaJ
    k/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRMwEQYDVQQDEwpF
    bmQgRW50aXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhauQDMJcCPPQQ
    87UeTX8Ue/b10HjppIrwo3Xs7bZWln+ImYWa8j5od4frntGfwLQX3KuJI6QdfhYj
    TE+oTfUxuHyq4xpJCfRLJtsnZzCCEgFK6Rq2wQxTi2z8L3pD7DM2fjKye9WqzwEU
    xhLsE/ItFHqLIVgUE0xGo5ryFpX/IwIDAQABo3UwczAhBgNVHREEGjAYgRZlbmQu
    ZW50aXR5QGV4YW1wbGUuY29tMB0GA1UdDgQWBBQXe5Iw/0TWZuGQECJsFk/AjkHd
    bTAfBgNVHSMEGDAWgBQIaK+FM8g5Snr4gpOOcGpKIIQsMjAOBgNVHQ8BAf8EBAMC
    BsAwDQYJKoZIhvcNAQEFBQADgYEAACAoNFtoMgG7CjYOrXHFlRrhBM+urcdiFKQb
    NjHA4gw92R7AANwQoLqFb0HLYnq3TGOBJl7SgEVeM+dwRTs5OyZKnDvyJjZpCHm7
    +5ZDd0thi6GrkWTg8zdhPBqjpMmKsr9z1E3kWORi6rwgdJKGDs6EYHbpc7vHhdOR
    RepiXc0=
    """.trimIndent()

    // https://datatracker.ietf.org/doc/html/rfc5280#appendix-C.3
    private val cert3 = """
    MIIDjjCCA06gAwIBAgICAQAwCQYHKoZIzjgEAzBHMRMwEQYKCZImiZPyLGQBGRYD
    Y29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEXMBUGA1UEAxMORXhhbXBsZSBE
    U0EgQ0EwHhcNMDQwNTAyMTY0NzM4WhcNMDUwNTAyMTY0NzM4WjBHMRMwEQYKCZIm
    iZPyLGQBGRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTEXMBUGA1UEAxMO
    RFNBIEVuZCBFbnRpdHkwggG3MIIBLAYHKoZIzjgEATCCAR8CgYEAtosPlCuazqUl
    xvLt/PuVMqwBEjO54BytkJu8SFSe85R3PCxxNVXm/k8iy9XYPomTM038vU9BZD6i
    mHDsMbRQ3uvxmCgKyT5Es/0il5aD0Bij4701W//uoyFyanuW2rk/HlqQryTWIPAN
    IafUArka/Kwh+56UnktCRZ5qskhj/kMCFQCyDbCxAd8MZiT8E5K6Vfd9V3SB5QKB
    gQCav0ax9T9EPcmlZfuRwI5H8QrDAUfCREI2qZKB3lfF4GiGWAB7H/mbd6HFEKWA
    kXhRUTz2/PzMRsaBeJKEPfSTPQw4fhpbmU6rFGT2DCEiTigInJK5Zp9A6JX21TEq
    7zmiYseybZ5YxDqoEYGEba/4tBm0whGu0CI7qiB/7h5XGAOBhAACgYAwtnX3fCAx
    rji7fg0rq6CcS98g1SQTPM2Y5V9st8G6SrqplYBT8A1y3DM39AEL9QQfnS4fYtiE
    OpslCVotyEaOK9T1DTvHLcZsuZjBJTpETo7KlWE1fM4VMVwjEx6iBdF6JBzL03IJ
    kP+bnSjAoQrsRp8NuNDc0BimK175j7WVvqOByjCBxzA5BgNVHREEMjAwhi5odHRw
    Oi8vd3d3LmV4YW1wbGUuY29tL3VzZXJzL0RTQWVuZGVudGl0eS5odG1sMCEGA1Ud
    EgQaMBiGFmh0dHA6Ly93d3cuZXhhbXBsZS5jb20wHQYDVR0OBBYEFN0lZpZDq3gR
    Q0T+lRb52ba3AmaNMB8GA1UdIwQYMBaAFIbKpSKBYu+tCom8rXJBLClJ9IZWMBcG
    A1UdIAQQMA4wDAYKYIZIAWUDAgEwCTAOBgNVHQ8BAf8EBAMCB4AwCQYHKoZIzjgE
    AwMvADAsAhRlVwc03dzKzF70AvRWQixe4bM7gAIUYPQxF8r0z//u9Ain2bJhvrHD
    2r8=
    """.trimIndent()

    // https://datatracker.ietf.org/doc/html/rfc5280#appendix-C.4
    private val crl = """
    MIIBYDCBygIBATANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29t
    MRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQRcN
    MDUwMjA1MTIwMDAwWhcNMDUwMjA2MTIwMDAwWjAiMCACARIXDTA0MTExOTE1NTcw
    M1owDDAKBgNVHRUEAwoBAaAvMC0wHwYDVR0jBBgwFoAUCGivhTPIOUp6+IKTjnBq
    SiCELDIwCgYDVR0UBAMCAQwwDQYJKoZIhvcNAQEFBQADgYEAItwYffcIzsx10NBq
    m60Q9HYjtIFutW2+DvsVFGzIF20f7pAXom9g5L2qjFXejoRvkvifEBInr0rUL4Xi
    NkR9qqNMJTgV/wD9Pn7uPSYS69jnK2LiK8NGgO94gtEVxtCccmrLznrtZ5mLbnCB
    fUNCdMGmr8FVF6IzTNYGmCuk/C4=
    """.trimIndent()

    /**
     * RSA Self-Signed Certificate (https://datatracker.ietf.org/doc/html/rfc5280#appendix-C.1)
     * This appendix contains an annotated hex dump of a 578 byte version 3 certificate.
     * The certificate contains the following information:
     *  - (a) the serial number is 17;
     *  - (b) the certificate is signed with RSA and the SHA-1 hash algorithm;
     *  - (c) the issuer's distinguished name is cn=Example CA,dc=example,dc=com;
     *  - (d) the subject's distinguished name is cn=Example CA,dc=example,dc=com;
     *  - (e) the certificate was issued on April 30, 2004 and expired on April 30, 2005;
     *  - (f) the certificate contains a 1024-bit RSA public key;
     *  - (g) the certificate contains a subject key identifier extension generated using method (1) of Section 4.2.1.2; and
     *  - (h) the certificate is a CA certificate (as indicated through the basic constraints extension).
     */
    @Test
    fun test1() {
        val base64EncodedCertificate = """
        MIICPjCCAaegAwIBAgIBETANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQB
        GRYDY29tMRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBs
        ZSBDQTAeFw0wNDA0MzAxNDI1MzRaFw0wNTA0MzAxNDI1MzRaMEMxEzARBgoJkiaJ
        k/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZFgdleGFtcGxlMRMwEQYDVQQDEwpF
        eGFtcGxlIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC15dtKHCqW88j
        LoBwOe7bb9Ut1WpPejQt+SJyR3Ad74DpyjCMAMSabltFtG6l5myUDfqR6UD8JZ3H
        t2gZVo8RcGrX8ckRTzp+P5mNbnaldF9epFVT5cdoNlPHHTsSpoX+vW6hyt81UKwI
        17m0flz+4qMs0SOEqpjAm2YYmmhH6QIDAQABo0IwQDAdBgNVHQ4EFgQUCGivhTPI
        OUp6+IKTjnBqSiCELDIwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
        DQYJKoZIhvcNAQEFBQADgYEAbPgCdKZh4mQEplQMbHITrTxH+/ZlE6mFkDPqdqMm
        2fzRDhVfKLfvk7888+I+fLlS/BZuKarh9Hpv1X/vs5XK82aIg06hNUWEy7ybuMit
        xV5G2QsOjYDhMyvcviuSfkpDqWrvimNhs25HOL7oDaNnXfP6kYE8krvFXyUl63zn
        2KE=
        """.trimIndent()
        val certificate = Der.decodeFromByteArray<Certificate>(Base64.Pem.decode(base64EncodedCertificate))

        println(certificate)
    }
}
