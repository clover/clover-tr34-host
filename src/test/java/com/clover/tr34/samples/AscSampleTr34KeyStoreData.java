package com.clover.tr34.samples;

import com.clover.tr34.Tr34CryptoUtils;
import com.clover.tr34.Tr34KdhRevocation;
import com.clover.tr34.Tr34KeyStoreData;
import com.clover.tr34.Tr34ScdKeyStoreData;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * Sample certificates and keys taken from X9 ASC TR34-2019 documentation.
 * <p>
 * Some of the samples appear to be non-conforming to standards such as DER and X.509.
 * Instances of this class are currently populated just enough to run some basic tests.
 */
public class AscSampleTr34KeyStoreData extends Tr34KeyStoreData {

    public static final String SAMPLE_ROOT_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDPDCCAiSgAwIBAgIFNAAAAAEwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMC\n" +
            "VVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEZMBcGA1UEAxMQVFIzNCBTYW1wbGUg\n" +
            "Um9vdDAeFw0xMDExMDIwMDAwMDBaFw0zMDEwMjcyMzU5NTlaMD8xCzAJBgNVBAYT\n" +
            "AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGTAXBgNVBAMTEFRSMzQgU2FtcGxl\n" +
            "IFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeZ10uwGLGQWI4\n" +
            "AG+CbKUnGCWD8q3S/owdgeatXsHoWzm+r5cIlNsrTyJ3OXlUHBIj1RqCth/1QYwe\n" +
            "XzZ5J8m6qsMvPhYgVdB3bsOSQiXD30LCI4/5qqo+ikcocVKs48ypFH1fgiC+c0hL\n" +
            "CN7XQ/ekPubrmGGZ0RFFC2oV8FB6tOBy3bjbFpbIAB/XmWd+g185anJp6twtesIK\n" +
            "vaod2I3UhW/xGhdqfDlAvH1gmszJ88Ud0AF8P+3Zx70L/er6CwkWH5xx6SrnOvF1\n" +
            "rbFTy+/OLDoPzeo5TEQjCjf4LtxEjrmwZp/ILpQ15pmprjGRrU7qXc0dLNw75sdR\n" +
            "B45sE4afAgMBAAGjPzA9MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIKDHIan\n" +
            "OuC29C5MzvfJw6JPSsnsMAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
            "zP2PtLg0ePSOxWB47oKHmrHUaBAaaC1RKYzcEyyTXwOdR1NuH0sB7Z5Si2nFJgsv\n" +
            "eFu2hixQLnhuXGP4gTOP/Mu5Kf5O4wi1D2xzGt6JVQIKW//eBgjeUd+GzRiHMPvM\n" +
            "TAb1DVf1DQRQ37kiJY6FlpxBBolmFzwmZkPp50vu3bgjSs1nAnG//PUXq03wqojh\n" +
            "Rqp1Q9MtGGpOnCv/mFyw3hR16Eqg9YVgTWg3wq+H74JZiWrTBq33kT9NMYf1jIMo\n" +
            "A1exxP5BvJaTBE2wcEPVAAdzjmeoFqUjWZGoBff8hT2KqDo01SC46Aa6z1bQZWhO\n" +
            "kCETYhPBMp8I9cRBZQS2/g==\n" +
            "-----END CERTIFICATE-----";

    // B.2.1.7 TR34 Sample KRD 1 Key
    public static final String SAMPLE_KRD_1_PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUXDDLb7sdOUzl\n" +
            "qHtJ223PFDSw+k4Ko3H4UO6Lrn8tw8VI1Ry9o90B8NZVO/t5hR5zFUOYSyLjYrT8\n" +
            "HdPW3oI3fSATLMY5Zd0K0t1onphSkWE1QPMOdaVY+RWy6eQN1CHKxr23RZD0Qoq0\n" +
            "aE7LQpTTutIS9mYiAO733cMBMW+6Z2txIPuRiTwroxGoT3OvIWO1YEQF/XYLsVJo\n" +
            "nPUgTyDLvZdiO125bM9ro4Jqw4eQ08LGbNfr/VyfHnDLx39Vj5VQGpqctKs9/aJl\n" +
            "0BCkmrcCoAFd8PbgjQzjYzBkHE3HXqj+fdXqaze9ZDKFd/hVDT8BWqVvGrXyXlX1\n" +
            "k0CvU/lVAgMBAAECggEBAIRrIDoa59CnRF4ImyhI3cY80UZyLmvP02eF/9m167P7\n" +
            "2W87BHr0TQHCzcPEbWEvMveMEORMJesoR7bWWpwnj4dOTMvoJYrxC86OAmYUTuNd\n" +
            "qAHvCCDCF2LNn0w7MGu3FYM+Plqj1GmbfKZWTJvOXsNQQWJ1puYZMun4rHp3+zV9\n" +
            "2JxeSS/jeY+gZCtNEtFTB59e/XePM0GyCgogLi+Zswd7WdBdLBVJviP5uvZZSfLG\n" +
            "zZsw0GABv4/mzce+64XtD7cTe7GFJ+JSB3nDWpqHZ7t6cM9OwSuuZSUrB02rIiby\n" +
            "6PoO0dweO3fpG0TIFV8/eJQCVb2qDWszt5R35Ze7tNkCgYEA89cBvXQP+sHjbvqf\n" +
            "euBcQaOYke2oUeAecBVp1tTfLP8qZK4juNjq11x0GDS1oVoYzP2Nwkks2LZDZDMe\n" +
            "WYKtXkXImkmOZaGBNI0/5/F3C/tFPt3W7/QT249sWayMJkkuDKl6kmSDX/Bg7/sr\n" +
            "MaJDxgSTyOjvjNieSy6GBvLBwf8CgYEA3vNLzDPe9HEqeCubKTD1doxevLDg5Pg1\n" +
            "1a61U+Tgrp7XuONh2VtnP6zpFcq7Psd1L2EeQdhGIBhf+zP2d55ib76dNOBrG85d\n" +
            "EiY5Qdu1FnHZDDvSnDN6AHsqZD//nHX6FgSN64PmhHvV2SyTjNUPdZU1WqN2TRzm\n" +
            "ebS5sipQnKsCgYEAkWgQkJJqiQUgA+kOOy8ZtMbCz5qiOhjk7b/HOqX8ZA/RjvJN\n" +
            "OQiZmk12qYydFxfsHCnDZC1QwfaGX3UgTw5fJg2FH4RnlvFlZBorFrxmWk2/sEqH\n" +
            "xtWNFewEF8GOXbJb9I8IGc44jXiBxfnIezOhKK9IFZHab+opEvouUGxo4K8CgYA0\n" +
            "tYRoBKNjWxXVT0nhlSeTHWCQb6jbuSrRF/ramLPd1MPffDJ39roUPcblVgaqsvEr\n" +
            "gGRs4LrDf7/BXemZIiLXlFMKWzw3WLR8Q/kpbs4DPms4DzSdpTXkwzmkddTyopm7\n" +
            "dtwuoAJxs+086OMBWqXLALmacibX2EtM3sNAMezY/QKBgQCjMcS9aViitfs68dA8\n" +
            "mazoZvUP4JjBguspTnpz31lMQiDn7HnK+vwWsmzgEhF4suuVf6+4f4mjr4AVg7E4\n" +
            "L1IdBgvzFM2hXXmgsTlazousJ/uE+513nwrNMqm2/O/iZe1yvCjMevBSVo+4CDa0\n" +
            "WETw0cEkmteh/Z9Z2IOVOoj82Q==\n" +
            "-----END PRIVATE KEY-----";

    public static final String SAMPLE_KRD_1_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDOTCCAiGgAwIBAgIFNAAAAAcwDQYJKoZIhvcNAQELBQAwQTELMAkGA1UEBhMC\n" +
            "VVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEbMBkGA1UEAxMSVFIzNCBTYW1wbGUg\n" +
            "Q0EgS1JEMB4XDTEwMTEwMjAwMDAwMFoXDTIwMTAyOTIzNTk1OVowQDELMAkGA1UE\n" +
            "BhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEaMBgGA1UEAxMRVFIzNCBTYW1w\n" +
            "bGUgS1JEIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUXDDLb7sd\n" +
            "OUzlqHtJ223PFDSw+k4Ko3H4UO6Lrn8tw8VI1Ry9o90B8NZVO/t5hR5zFUOYSyLj\n" +
            "YrT8HdPW3oI3fSATLMY5Zd0K0t1onphSkWE1QPMOdaVY+RWy6eQN1CHKxr23RZD0\n" +
            "Qoq0aE7LQpTTutIS9mYiAO733cMBMW+6Z2txIPuRiTwroxGoT3OvIWO1YEQF/XYL\n" +
            "sVJonPUgTyDLvZdiO125bM9ro4Jqw4eQ08LGbNfr/VyfHnDLx39Vj5VQGpqctKs9\n" +
            "/aJl0BCkmrcCoAFd8PbgjQzjYzBkHE3HXqj+fdXqaze9ZDKFd/hVDT8BWqVvGrXy\n" +
            "XlX1k0CvU/lVAgMBAAGjOTA3MAkGA1UdEwQCMAAwHQYDVR0OBBYEFA1yBTypguLB\n" +
            "ic5HIFDTTQRamlnTMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEADZ7T\n" +
            "nJfS4XvwcTTbQLoaSs7XKtaP1RnePiL5uMtqUYBbX81DjxxzCX5pmfBcwG+8e/I/\n" +
            "yxJBEo4KedeTUWAGhRjRimUw+0hjN8l/DK1xjKHcJIHyHB994D7FaxLOqCvIHr30\n" +
            "lEJ1b/PamS0owURXR6sQIfHBT/5D0IUo5mjgQG3/UA1VXYI7nwtRxLvbR8bxezAn\n" +
            "R5tci+RIQnbtC3HNrcHCSUa20YZGjIV047jR6hUf2JQiG9v0wuc8lAXXlee3/eIZ\n" +
            "muMxdtOucq2oDZUQIE8MhwV3t/dS3EebKdUBITkcz8qBeMhrGq12m1hOaBfhYrBa\n" +
            "MRkw+KTx3ddSdCDXsQ==\n" +
            "-----END CERTIFICATE-----";

    public static final String SAMPLE_KDH_1_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDUTCCAjmgAwIBAgIFNAAAAAYwDQYJKoZIhvcNAQELBQAwQTELMAkGA1UEBhMC\n" +
            "VVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEbMBkGA1UEAxMSVFIzNCBTYW1wbGUg\n" +
            "Q0EgS0RIMB4XDTEwMTEwMjAwMDAwMFoXDTIwMTAyOTIzNTk1OVowQDELMAkGA1UE\n" +
            "BhMCVVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEaMBgGA1UEAxMRVFIzNCBTYW1w\n" +
            "bGUgS0RIIDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDD648pBL7L\n" +
            "b5Hvyjjbt13ZGTHKj+IRZj9Ib8q6B6DC7YfLUobFCNotHw7e3cCn21xgXby5q3PR\n" +
            "YbsaDxsO5VV4D697yrpeBt/viJ5R9o/mXcIa8AA6hvFwbkYeFQK+pFh3uuICZY+8\n" +
            "ouvtVpIBhjV/cU5b7slwoeqICKn0Ji8vZEOCedh8ZMF+ObpxMPR7SqRBNkP4aphi\n" +
            "o1rZNz2OLSjFksilIXMbqVyORDJ6uw7OUL+ubOjq9JNOlIxqO4vr4mimknvIfhrn\n" +
            "ktUxUzmbS4KILJp55DHRDc5YQHBTuSv21tZyKbtyquAQgn5xJtdXBAbKqp9NtPKM\n" +
            "S9ZKnvyYoOrNAgMBAAGjUTBPMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgbAMAkGA1Ud\n" +
            "EwQCMAAwHQYDVR0OBBYEFA8RoQrHXhlpbL0WonoyGxhajYcHMAsGA1UdDwQEAwIG\n" +
            "wDANBgkqhkiG9w0BAQsFAAOCAQEAjadCTzoj3bOETDwaxSm3rRO/pbKj86kUVQL7\n" +
            "rFQIgqZTkIGY/ljVwlJpNReYCVeJKAnpNEDw1+IWO/QoLDLy1XyZhGj4luLGqO4v\n" +
            "HrdsA8g9j4Wj60+G7I+P/RJuP2orslSLV7JTiKwvrMI8jPUv0I3Q7ADbDH7MCCHG\n" +
            "gd+ubgVCWWt0vYXIbzfXpB6Q0bMjjHlQAklqq4oAGrvEr/mcVNbNAXR2Ind+IPQB\n" +
            "SBAjlWsUN87K5SkeSTO+EU/OG4I+TFFVy7gxQr0VQ4KbCK4fTIcYcZgtiorW6If0\n" +
            "C1gvjNMu6DCl1aTjAzp6QV/rkYG+1Lk91eN8BF5jKBPOQMScrA==\n" +
            "-----END CERTIFICATE-----";

    public static final String SAMPLE_KDH_1_PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDD648pBL7Lb5Hv\n" +
            "yjjbt13ZGTHKj+IRZj9Ib8q6B6DC7YfLUobFCNotHw7e3cCn21xgXby5q3PRYbsa\n" +
            "DxsO5VV4D697yrpeBt/viJ5R9o/mXcIa8AA6hvFwbkYeFQK+pFh3uuICZY+8ouvt\n" +
            "VpIBhjV/cU5b7slwoeqICKn0Ji8vZEOCedh8ZMF+ObpxMPR7SqRBNkP4aphio1rZ\n" +
            "Nz2OLSjFksilIXMbqVyORDJ6uw7OUL+ubOjq9JNOlIxqO4vr4mimknvIfhrnktUx\n" +
            "UzmbS4KILJp55DHRDc5YQHBTuSv21tZyKbtyquAQgn5xJtdXBAbKqp9NtPKMS9ZK\n" +
            "nvyYoOrNAgMBAAECggEAduG92b72Yw1NOXq0q6YFfVGLZAWQwMwRREwJcH5mb0Gg\n" +
            "r6BhBLhNYynAZT2bxH8X+6WFeghuW7P4y2Q1IAHKrfKeofguxBVZ1shIgSWixb9I\n" +
            "o/3Tta/iWz2esGxBYRrqT6SHtbqY0Hbvv/FS4TflyHIhgSlQ9FZbsLXJIsv0v8T/\n" +
            "G+lpsa9pNgTFzI+oTpFQLSWAmTy7pmHAtjckX8V0IynWkdSYQ70MLOYeUsMFDMQq\n" +
            "WL9vOozA1BkVIk82OfJbd7x69MylHvAslblFjaRphka2VGPRACRxjH0W7iyuLUP/\n" +
            "ldonALKZKuFOIPvEjXMU/DJzxAG7JlWfncyEe41/RQKBgQD2x7Md9KPd+HPpVsCT\n" +
            "vZva56sKlg8JvgcYFeLqUdMF9QyKIDzLdZFpWsk9vmzFLVNABhWnIQkcu4gNqe/z\n" +
            "obTUJEvHGaCpyub8hC8kNdQ7FbH53T2S69VtwIzNZl70qHNfCbIpjf+RGsZk5QCG\n" +
            "XUbNjDmPLaKFoQbdBQT0qYVeowKBgQDLPWpfVGGtx5BmTZNVmJ/hAS9PqoNwL7wq\n" +
            "GD9UIzb7PUD/bWUvc75uQrqVMoqH62MTQdGTd8O42XMqUHyRY0LfaJjryu26rrKV\n" +
            "RRr/nMby0L3lNZD2YZpLLOs3EK8UTk3A83X2IesIuusyTDt/qKyRJxB0qCAUEXiT\n" +
            "t7ZATOBXzwKBgHLVOmQWEqqXklhiJfqZoIycgNrMOPMvmd17Ubv3l1qOTOd5WNDU\n" +
            "RHXh6QLyOWsHTFXefvTmSnc0THsPOLkF5j9RJHHhWwGniRS37bfL1JYp4keCy8Qy\n" +
            "OX54uwxZNpZiTE1NFbqAeQvsiaUparUbcnbzaVVWxumnpKn0S/oNaCJBAoGAfA4h\n" +
            "1syHzu5IStnBO/csZ8g0W7ll/11zynIAfdf84IA0I3Vf1QYeT+k1QIqYGnzofcGo\n" +
            "Lg5ljnhUnpiAYLIpCHstFIhKca/e29RRtYK5wU7/CmCW+nz7FDX34SWy6H8fYM56\n" +
            "y2FKuIp3s7zqeHK52uPwXHSfGADOC8SQX1FNgusCgYEAn9iVx8wnQqmbD8lwWDh6\n" +
            "L6vjKEpjuy76P9Jnp1cGgV15rG1UzOLYNtwB7dDVWH8wfOICLHbO91J9FN7h+SV+\n" +
            "ZFqArTbwa7QeH+xpYXuJ0a1H13994ynWb2l6OnyChNSqeqslTZgtiHVCy10G/+N0\n" +
            "ofXkAMX7ejLOcHphTyLAHdY=\n" +
            "-----END PRIVATE KEY-----";

    // B.4 CAKDH – Certificate Authority – KDH Certificate
    public static final String SAMPLE_CA_KDH_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDPjCCAiagAwIBAgIFNAAAAAUwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMC\n" +
            "VVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEZMBcGA1UEAxMQVFIzNCBTYW1wbGUg\n" +
            "Um9vdDAeFw0xMDExMDIwMDAwMDBaFw0yNTEwMjgyMzU5NTlaMEExCzAJBgNVBAYT\n" +
            "AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGzAZBgNVBAMTElRSMzQgU2FtcGxl\n" +
            "IENBIEtESDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK76HXOWw9uk\n" +
            "meVdeqUHFKxedcEnHZAA6u7SoAerZGZwUV9DISyKILwyy2exzV1xL2Z3b3dtWLxf\n" +
            "gXMMU5Y2IitEKMiq/PzQDLzoSXBwZsGUbQ6vsjMTtqatvyPpIvWV0e5XpsS+AU1q\n" +
            "ZOXZxFQpySBBDh8Swl5VAAZdSXpHeM8DVg3oEYbO1+W3R0odRwPqr5RAajxzFE34\n" +
            "yXH4ec8zro6YSN5QUbRgKaYslJe86GrxUkYLOUOuJM/5zoj1pQSF2hSz0x3Txp3y\n" +
            "QQXSUmJT6jiJ/hxv2DOoE69D/sQMQPiC2t5O6/5YAUSN3L2d5Pu2nVaggQ4IK3Mq\n" +
            "NeoqFnByhv8CAwEAAaM/MD0wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUuCpY\n" +
            "Cg159koHx1irw5NlY183yhgwCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCb+yPhlvcoHPANAfIV6DVxd7CoPzLihuz4VjE24OQZ8LvIa5l++fmeD3mwonKO\n" +
            "CVAu1zBO1qzguAP1nybImPeoFPpMGUq0A+HpmY0cFhUW5HcYrFp4UnUyPqOtmKVA\n" +
            "7kr2W5qMPoMcuDO778vNQXNDyeskBOi+LMfdVy1OFIW7OS+L9xp5L2k4koMCyjse\n" +
            "65sUl87YMe+EOqVYWCImFmgjilnAn2uF3cn9BheEXstxyPJ7RNxLFPNqv7lFQkgm\n" +
            "SfKTqvfEYirqrAinZBVp9uU6ZOEE+C84pKCXZDrcuQf8EVJK9HLX0NCQcxfD32OU\n" +
            "7N32YnGn+yrjDPjVgXyDVt+D\n" +
            "-----END CERTIFICATE-----";

    public static final String SAMPLE_CA_KRD_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDPjCCAiagAwIBAgIFNAAAAAYwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMC\n" +
            "VVMxFTATBgNVBAoTDFRSMzQgU2FtcGxlczEZMBcGA1UEAxMQVFIzNCBTYW1wbGUg\n" +
            "Um9vdDAeFw0xMDExMDIwMDAwMDBaFw0yNTEwMjgyMzU5NTlaMEExCzAJBgNVBAYT\n" +
            "AlVTMRUwEwYDVQQKEwxUUjM0IFNhbXBsZXMxGzAZBgNVBAMTElRSMzQgU2FtcGxl\n" +
            "IENBIEtSRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPv35H8/s7H0\n" +
            "1BV+yYpfxYVMNClfxriHb0BbDjftnT5aTOmWHBOkRzDk6Jeqkna9IDDzRSO6mVfw\n" +
            "VnugU6k07JWSPrOQXvrhnKADkXjJwfCEaD4lJwpzVhbkuhSlXfyTv6yECHoivCkH\n" +
            "GDAzSL4XosYBWUX9mhRwXXxDupSA12I/u0aNJLYSBGb58Ifj14m4Kikc4Xi5yK/j\n" +
            "AYSny4dpYg9OzG0hK0U49G6aF4qyy+esrs8dkRZO0O9ZM0BEfnhQ/315PcSFEohO\n" +
            "IOCd6oAJCWOEdjW+0+khdN+pgjhB0O+JEtwie6MMaBMzaEbZQSSNwNTw4tJZZYJY\n" +
            "7RoCGEcp4tsCAwEAAaM/MD0wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUEjhu\n" +
            "z7ambtrb/wlvZbvVsFD5zA0wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQBrI0JF1yANFBgdYHrGznNY2XXSPaMD8h9UuN6696aIy1zlBSIySt2S0LgTMXq9\n" +
            "lhrUHRB1djmoyNYYXczI3wY+C11JBrIfrkEWHJE3UxqJyxGY9yHlV6SqeqKMnoaZ\n" +
            "g/BsaUMTTKAlOShoOt4TNk6/wiSqfh28IL2HkW7vvwDaIC8PRt5u/GF4440smsNv\n" +
            "yYt9+sFAsjlimsVh4oT1bQmuGoeO6QB+EFmXxddNGsf5cDx4KyQlGPFzMJu5ugCo\n" +
            "d6R4IvyFnh49YV9V0QoMWYhHP6WEhmc2P66kp2EpVlqweY1+3hoYulS2AClszjYz\n" +
            "IoRAf/W3NJh9YlwyHkAAT2Xh\n" +
            "-----END CERTIFICATE-----";

    private final X509Certificate rootCert;
    private final X509Certificate krdCaCert;
    private final X509Certificate kdhCaCert;
    private final X509Certificate kdhCert;

    private final PrivateKey krdCaPrivateKey;
    private final PrivateKey kdhCaPrivateKey;
    private final PrivateKey kdhPrivateKey;

    private final List<X509Certificate> kdhIssuerChain;

    private AscSampleTr34KeyStoreData(String kdhCertPem, String kdhPrivateKeyPem, String... kdhIssuerChainPem) {
        kdhCert = Tr34CryptoUtils.parseCert(kdhCertPem);
        if (kdhPrivateKeyPem != null) {
            kdhPrivateKey = Tr34CryptoUtils.parsePrivateKey(kdhPrivateKeyPem);
        } else {
            kdhPrivateKey = null;
        }

        rootCert = Tr34CryptoUtils.parseCert(SAMPLE_ROOT_CERT_PEM);
        kdhCaCert = Tr34CryptoUtils.parseCert(SAMPLE_CA_KDH_CERT_PEM);
        krdCaCert = null;

        kdhCaPrivateKey = null;
        krdCaPrivateKey = Tr34CryptoUtils.parsePrivateKey(SAMPLE_KRD_1_PRIVATE_KEY_PEM);

        List<X509Certificate> chain = new LinkedList<>();
        for (String certPem : kdhIssuerChainPem) {
            chain.add(Tr34CryptoUtils.parseCert(certPem));
        }

        kdhIssuerChain = Collections.unmodifiableList(chain);

        verifyKdh();
    }

    public static final Tr34KeyStoreData KDH_1 =
            new AscSampleTr34KeyStoreData(SAMPLE_KDH_1_CERT_PEM, SAMPLE_KDH_1_PRIVATE_KEY_PEM, SAMPLE_CA_KDH_CERT_PEM, SAMPLE_ROOT_CERT_PEM);

    @Override
    public X509Certificate getRootCert() {
        return rootCert;
    }

    @Override
    public List<X509Certificate> getKdhIssuerChain() {
        return kdhIssuerChain;
    }

    @Override
    public X509Certificate getKdhCert() {
        return kdhCert;
    }

    @Override
    public X509Certificate getKrdCaCert() {
        return krdCaCert;
    }

    @Override
    public Tr34ScdKeyStoreData getKdhKeyStoreData() {
        return new Tr34ScdKeyStoreData(kdhCert, kdhPrivateKey);
    }

    @Override
    public Tr34ScdKeyStoreData getKdhCaKeyStoreData() {
        return new Tr34ScdKeyStoreData(kdhCaCert, kdhCaPrivateKey);
    }

    @Override
    public Tr34ScdKeyStoreData getKrdCaKeyStoreData() {
        return new Tr34ScdKeyStoreData(krdCaCert, krdCaPrivateKey);
    }

    @Override
    public List<Tr34KdhRevocation> getKdhRevocationList() {
        return Arrays.asList(
                new Tr34KdhRevocation(BigInteger.valueOf(223338299400L), new Date(1288718893000L), CRLReason.CESSATION_OF_OPERATION),
                new Tr34KdhRevocation(BigInteger.valueOf(223338299402L), new Date(1288719106000L), CRLReason.CESSATION_OF_OPERATION),
                new Tr34KdhRevocation(BigInteger.valueOf(223338299403L), new Date(1288719205000L), CRLReason.CESSATION_OF_OPERATION)
        );
    }

    @Override
    public int nextCrlUpdateDays() {
        return 30;
    }
}
