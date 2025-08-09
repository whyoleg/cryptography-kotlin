/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem.benchmarks

import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.benchmark.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@State(Scope.Benchmark)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@OutputTimeUnit(BenchmarkTimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.Throughput)
class PemBenchmark {
    @Param("privateKey", "certificate", "googleCertificateChain")
    var testCaseString: String = ""
    lateinit var testCase: TestCase

    @Setup
    fun setup() {
        testCase = when (testCaseString) {
            "privateKey"             -> TestCase.privateKey
            "certificate"            -> TestCase.certificate
            "googleCertificateChain" -> TestCase.googleCertificateChain
            else                     -> error("Unknown test case: $testCaseString")
        }
        println(testCase.documentString)
    }

    @Benchmark
    fun encodeToString(): String {
        return testCase.document.encodeToString()
    }

    @Benchmark
    fun encodeToByteString(): ByteString {
        return testCase.document.encodeToByteString()
    }

    @Benchmark
    fun encodeToSink(): Sink {
        return Buffer().also { testCase.document.encodeToSink(it) }
    }

    @Benchmark
    fun decodeFromString(): PemDocument {
        return PemDocument.decode(testCase.documentString)
    }

    @Benchmark
    fun decodeFromByteString(): PemDocument {
        return PemDocument.decode(testCase.documentBytes)
    }

    @Benchmark
    fun decodeFromSource(): PemDocument {
        return PemDocument.decode(Buffer().also { it.write(testCase.documentBytes) })
    }

    @Benchmark
    fun decodeToSequenceFromString(): List<PemDocument> {
        return PemDocument.decodeToSequence(testCase.documentString).toList()
    }

    @Benchmark
    fun decodeToSequenceFromByteString(): List<PemDocument> {
        return PemDocument.decodeToSequence(testCase.documentBytes).toList()
    }

    @Benchmark
    fun decodeToSequenceFromSource(): List<PemDocument> {
        return PemDocument.decodeToSequence(Buffer().also { it.write(testCase.documentBytes) }).toList()
    }

    class TestCase private constructor(
        val document: PemDocument,
        val documentString: String,
        val documentBytes: ByteString,
    ) {
        companion object {
            private fun String.toTestCase() = TestCase(
                document = PemDocument.decode(this),
                documentString = this,
                documentBytes = this.encodeToByteString()
            )

            val privateKey = """
                -----BEGIN PRIVATE KEY-----
                MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAU9BD0jxDfF5OV380z
                9VIEUN2W5kJDZ3hbuaDenCxLiAMsoquKTfFaou71eLdN0TShZANiAARMUhCee/cp
                xmjGc1roj0D0k6VlUqtA+JVCWigXcIAukOeTHCngZDKCrD4PkXDBvbciJdZKvO+l
                ml2FIkoovZh/8yeTKmjUMb804g6OmjUc9vVojCRV0YdaSmYkkJMJbLg=
                -----END PRIVATE KEY-----
            """.trimIndent().toTestCase()

            val certificate = """
                -----BEGIN CERTIFICATE-----
                MIIH/TCCBeWgAwIBAgIQaBYE3/M08XHYCnNVmcFBcjANBgkqhkiG9w0BAQsFADBy
                MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
                ETAPBgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIEVWIFNTTCBJbnRl
                cm1lZGlhdGUgQ0EgUlNBIFIzMB4XDTIwMDQwMTAwNTgzM1oXDTIxMDcxNjAwNTgz
                M1owgb0xCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
                c3RvbjERMA8GA1UECgwIU1NMIENvcnAxFjAUBgNVBAUTDU5WMjAwODE2MTQyNDMx
                FDASBgNVBAMMC3d3dy5zc2wuY29tMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXph
                dGlvbjEXMBUGCysGAQQBgjc8AgECDAZOZXZhZGExEzARBgsrBgEEAYI3PAIBAxMC
                VVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHheRkbb1FCc7xRKst
                wK0JIGaKY8t7JbS2bQ2b6YIJDgnHuIYHqBrCUV79oelikkokRkFvcvpaKinFHDQH
                UpWEI6RUERYmSCg3O8Wi42uOcV2B5ZabmXCkwdxY5Ecl51BbM8UnGdoAGbdNmiRm
                SmTjcs+lhMxg4fFY6lBpiEVFiGUjGRR+61R67Lz6U4KJeLNcCm07QwFYKBmpi08g
                dygSvRdUw55Jopredj+VGtjUkB4hFT4GQX/ght69Rlqz/+8u0dEQkhuUuucrqalm
                SGy43HRwBfDKFwYeWM7CPMd5e/dO+t08t8PbjzVTTv5hQDCsEYIV2T7AFI9ScNxM
                kh7/AgMBAAGjggNBMIIDPTAfBgNVHSMEGDAWgBS/wVqH/yj6QT39t0/kHa+gYVgp
                vTB/BggrBgEFBQcBAQRzMHEwTQYIKwYBBQUHMAKGQWh0dHA6Ly93d3cuc3NsLmNv
                bS9yZXBvc2l0b3J5L1NTTGNvbS1TdWJDQS1FVi1TU0wtUlNBLTQwOTYtUjMuY3J0
                MCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTAfBgNVHREEGDAWggt3
                d3cuc3NsLmNvbYIHc3NsLmNvbTBfBgNVHSAEWDBWMAcGBWeBDAEBMA0GCyqEaAGG
                9ncCBQEBMDwGDCsGAQQBgqkwAQMBBDAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3
                dy5zc2wuY29tL3JlcG9zaXRvcnkwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF
                BwMBMEgGA1UdHwRBMD8wPaA7oDmGN2h0dHA6Ly9jcmxzLnNzbC5jb20vU1NMY29t
                LVN1YkNBLUVWLVNTTC1SU0EtNDA5Ni1SMy5jcmwwHQYDVR0OBBYEFADAFUIazw5r
                ZIHapnRxIUnpw+GLMA4GA1UdDwEB/wQEAwIFoDCCAX0GCisGAQQB1nkCBAIEggFt
                BIIBaQFnAHcA9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOMAAAFxM0ho
                bwAABAMASDBGAiEA6xeliNR8Gk/63pYdnS/vOx/CjptEMEv89WWh1/urWIECIQDy
                BreHU25DzwukQaRQjwW655ZLkqCnxbxQWRiOemj9JAB1AJQgvB6O1Y1siHMfgosi
                LA3R2k1ebE+UPWHbTi9YTaLCAAABcTNIaNwAAAQDAEYwRAIgGRE4wzabNRdD8kq/
                vFP3tQe2hm0x5nXulowh4Ibw3lkCIFYb/3lSDplS7AcR4r+XpWtEKSTFWJmNCRbc
                XJur2RGBAHUA7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfkAAAFxM0ho
                8wAABAMARjBEAiB6IvboWss3R4ItVwjebl7D3yoFaX0NDh2dWhhgwCxrHwIgCfq7
                ocMC5t+1ji5M5xaLmPC4I+WX3I/ARkWSyiO7IQcwDQYJKoZIhvcNAQELBQADggIB
                ACeuur4QnujqmguSrHU3mhf+cJodzTQNqo4tde+PD1/eFdYAELu8xF+0At7xJiPY
                i5RKwilyP56v+3iY2T9lw7S8TJ041VLhaIKp14MzSUzRyeoOAsJ7QADMClHKUDlH
                UU2pNuo88Y6igovT3bsnwJNiEQNqymSSYhktw0taduoqjqXn06gsVioWTVDXysd5
                qEx4t6sIgIcMm26YH1vJpCQEhKpc2y07gRkklBZRtMjThv4cXyyMX7uTcdT7AJBP
                ueifCoV25JxXuo8d5139gwP1BAe7IBVPx2u7KN/UyOXdZmwMf/TmFGwDdCfsyHf/
                ZsB2wLHozTYoAVmQ9FoU1JLgcVivqJ+vNlBhHXhlxMdN0j80R9Nz6EIglQjeK3O8
                I/cFGm/B8+42hOlCId9ZdtndJcRJVji0wD0qwevCafA9jJlHv/jsE+I9Uz6cpCyh
                sw+lrFdxUgqU58axqeK89FR+No4q0IIO+Ji1rJKr9nkSB0BqXozVnE1YB/KLvdIs
                uYZJuqb2pKku+zzT6gUwHUTZvBiNOtXL4Nxwc/KT7WzOSd2wP10QI8DKg4vfiNDs
                HWmB1c4Kji6gOgA5uSUzaGmq/v4VncK5Ur+n9LbfnfLc28J5ft/GotinMyDk3iar
                F10YlqcOmeX1uFmKbdi/XorGlkCoMF3TDx8rmp9DBiB/
                -----END CERTIFICATE-----
            """.trimIndent().toTestCase()

            // obtained via `openssl s_client -showcerts -connect www.google.com:443`
            val googleCertificateChain = """
                 0 s:CN=www.google.com
                   i:C=US, O=Google Trust Services, CN=WR2
                   a:PKEY: EC, (prime256v1); sigalg: sha256WithRSAEncryption
                   v:NotBefore: Jul  7 08:35:54 2025 GMT; NotAfter: Sep 29 08:35:53 2025 GMT
                -----BEGIN CERTIFICATE-----
                MIIEVTCCAz2gAwIBAgIQc5TC2nLrVf4Kw1L8a17XyTANBgkqhkiG9w0BAQsFADA7
                MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQww
                CgYDVQQDEwNXUjIwHhcNMjUwNzA3MDgzNTU0WhcNMjUwOTI5MDgzNTUzWjAZMRcw
                FQYDVQQDEw53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
                BFmUG28uSHjAsoydiumyqhnoajtKYozAT/X65vdUpoAPSXIfQw1DCKViQYulxD/g
                OvCehyBe1N9yPltsjVc+h4ujggJAMIICPDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
                BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUiH5egx0TI4Ua
                sEH2WJrxdEF8gBEwHwYDVR0jBBgwFoAU3hse7XkV1D43JMMhu+w0OW1CsjAwWAYI
                KwYBBQUHAQEETDBKMCEGCCsGAQUFBzABhhVodHRwOi8vby5wa2kuZ29vZy93cjIw
                JQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMi5jcnQwGQYDVR0RBBIw
                EIIOd3d3Lmdvb2dsZS5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8w
                LTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd3IyL29CRllZYWh6Z1ZJLmNybDCC
                AQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2ABLxTjS9U3JMhAYZw48/ehP457Vih4ic
                bTAFhOvlhiY6AAABl+Q9944AAAQDAEcwRQIgNMV+Fyvcr8rZZ0OvGOp0XCYKOulz
                9XF9tj85yuDUdh4CIQDK1tH0LtM8oNxpm6/C2/C1+ROIBwTNuH5yuy1TPPitLQB1
                AH1ZHhLheCp7HGFnfF79+NCHXBSgTpWeuQMv2Q6MLnm4AAABl+Q9+5kAAAQDAEYw
                RAIgQCJu1pJLtphnMFc8XjahvFzg8vXAVwaciYiDqh67wFQCIG8JlXQ9j0muZe2O
                0lefKSAgVv2sUemqoEovPbjLy5uPMA0GCSqGSIb3DQEBCwUAA4IBAQByr/DYf3Xo
                tsnfDqmdZHC4y7K8XoB8+2wfIS18VCm/sxcgXqgjzn7m5WCxDozE4Jv0OhOvaARq
                IJMVDndWu2BEoZE2Xc9nKKvLxj9Lv8dLvdHDSwWqIGp1HlOy+1o4U5/inG3FSxY2
                /VfM8uobBRMIQLakyMt4YWUU05j+srElxHBgThSlWFlB4/W7nkhR3eBNyWXNw5t9
                GOO4VDp3X7V85R1fJ/qG/N57LSXLsaC4MajvWOobskqMPlZadhwHbwPcX77l7LT9
                szAUorBmGkWg7wbZL817rAxWCQW83Fzbgkv5pSBcO3R4r4Pz4Eq7Js6zOXatFGx+
                Ddy8ixB59aM5
                -----END CERTIFICATE-----
                 1 s:C=US, O=Google Trust Services, CN=WR2
                   i:C=US, O=Google Trust Services LLC, CN=GTS Root R1
                   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
                   v:NotBefore: Dec 13 09:00:00 2023 GMT; NotAfter: Feb 20 14:00:00 2029 GMT
                -----BEGIN CERTIFICATE-----
                MIIFCzCCAvOgAwIBAgIQf/AFoHxM3tEArZ1mpRB7mDANBgkqhkiG9w0BAQsFADBH
                MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
                QzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjMxMjEzMDkwMDAwWhcNMjkwMjIw
                MTQwMDAwWjA7MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNl
                cnZpY2VzMQwwCgYDVQQDEwNXUjIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
                AoIBAQCp/5x/RR5wqFOfytnlDd5GV1d9vI+aWqxG8YSau5HbyfsvAfuSCQAWXqAc
                +MGr+XgvSszYhaLYWTwO0xj7sfUkDSbutltkdnwUxy96zqhMt/TZCPzfhyM1IKji
                aeKMTj+xWfpgoh6zySBTGYLKNlNtYE3pAJH8do1cCA8Kwtzxc2vFE24KT3rC8gIc
                LrRjg9ox9i11MLL7q8Ju26nADrn5Z9TDJVd06wW06Y613ijNzHoU5HEDy01hLmFX
                xRmpC5iEGuh5KdmyjS//V2pm4M6rlagplmNwEmceOuHbsCFx13ye/aoXbv4r+zgX
                FNFmp6+atXDMyGOBOozAKql2N87jAgMBAAGjgf4wgfswDgYDVR0PAQH/BAQDAgGG
                MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/
                AgEAMB0GA1UdDgQWBBTeGx7teRXUPjckwyG77DQ5bUKyMDAfBgNVHSMEGDAWgBTk
                rysmcRorSCeFL1JmLO/wiRNxPjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAKG
                GGh0dHA6Ly9pLnBraS5nb29nL3IxLmNydDArBgNVHR8EJDAiMCCgHqAchhpodHRw
                Oi8vYy5wa2kuZ29vZy9yL3IxLmNybDATBgNVHSAEDDAKMAgGBmeBDAECATANBgkq
                hkiG9w0BAQsFAAOCAgEARXWL5R87RBOWGqtY8TXJbz3S0DNKhjO6V1FP7sQ02hYS
                TL8Tnw3UVOlIecAwPJQl8hr0ujKUtjNyC4XuCRElNJThb0Lbgpt7fyqaqf9/qdLe
                SiDLs/sDA7j4BwXaWZIvGEaYzq9yviQmsR4ATb0IrZNBRAq7x9UBhb+TV+PfdBJT
                DhEl05vc3ssnbrPCuTNiOcLgNeFbpwkuGcuRKnZc8d/KI4RApW//mkHgte8y0YWu
                ryUJ8GLFbsLIbjL9uNrizkqRSvOFVU6xddZIMy9vhNkSXJ/UcZhjJY1pXAprffJB
                vei7j+Qi151lRehMCofa6WBmiA4fx+FOVsV2/7R6V2nyAiIJJkEd2nSi5SnzxJrl
                Xdaqev3htytmOPvoKWa676ATL/hzfvDaQBEcXd2Ppvy+275W+DKcH0FBbX62xevG
                iza3F4ydzxl6NJ8hk8R+dDXSqv1MbRT1ybB5W0k8878XSOjvmiYTDIfyc9acxVJr
                Y/cykHipa+te1pOhv7wYPYtZ9orGBV5SGOJm4NrB3K1aJar0RfzxC3ikr7Dyc6Qw
                qDTBU39CluVIQeuQRgwG3MuSxl7zRERDRilGoKb8uY45JzmxWuKxrfwT/478JuHU
                /oTxUFqOl2stKnn7QGTq8z29W+GgBLCXSBxC9epaHM0myFH/FJlniXJfHeytWt0=
                -----END CERTIFICATE-----
                 2 s:C=US, O=Google Trust Services LLC, CN=GTS Root R1
                   i:C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA
                   a:PKEY: RSA, 4096 (bit); sigalg: sha256WithRSAEncryption
                   v:NotBefore: Jun 19 00:00:42 2020 GMT; NotAfter: Jan 28 00:00:42 2028 GMT
                -----BEGIN CERTIFICATE-----
                MIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX
                MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE
                CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx
                OTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT
                GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx
                MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63
                ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS
                iV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k
                KSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ
                DrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk
                j5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5
                cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW
                CruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499
                iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei
                Eua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap
                sZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b
                9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP
                BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf
                BgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw
                JQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH
                MAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al
                oCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy
                MAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF
                AwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9
                NR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9
                WprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw
                9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy
                +qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi
                d0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=
                -----END CERTIFICATE-----
            """.trimIndent().toTestCase()
        }
    }
}
