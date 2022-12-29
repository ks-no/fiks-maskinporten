package no.ks.fiks.maskinporten

import io.kotest.core.spec.style.StringSpec
import io.mockk.every
import io.mockk.mockk
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikatAutoConfigure
import no.ks.fiks.virksomhetsertifikat.VirksomhetSertifikater
import org.assertj.core.api.Assertions.assertThat
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import java.math.BigInteger
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*
import kotlin.random.Random


class MaskinportenAutoConfigureTest : StringSpec() {


    init {
        "Autoconfigures Maskinportenklient" {
            val issuer = "issuer"
            val audience = "audience"
            val tokenEndpoint = "https://somewhere"
            val privateKeyName = "privateKey"

            val keyStoreMock = mockk<KeyStore> {
                every { getKey(privateKeyName, any()) } returns mockPrivateKey
                every { getCertificate(privateKeyName) } returns mockCertificate
            }
            val virksomhetSertifikatStore = mockk<VirksomhetSertifikater.KsVirksomhetSertifikatStore> {
                every { keyStore } returns keyStoreMock
                every { privateKeyAlias } returns privateKeyName
                every { privateKeyPassword } returns "privateKeyPassword".toCharArray()
            }
            val virksomhetSertifikater = mockk<VirksomhetSertifikater> {
                every { requireAuthKeyStore() } returns virksomhetSertifikatStore
            }
            contextRunner
                .withPropertyValues(
                    "maskinporten.audience=$audience",
                    "maskinporten.tokenEndpoint=$tokenEndpoint",
                    "maskinporten.issuer=$issuer"
                )
                .withConfiguration(AutoConfigurations.of(VirksomhetSertifikatAutoConfigure::class.java))
                .withBean(VirksomhetSertifikater::class.java, { virksomhetSertifikater })
                .run { context ->
                    assertThat(context).hasSingleBean(Maskinportenklient::class.java)
                }
        }

        "Does not autoconfigure if no Virksomhetssertifikater bean exists" {
            contextRunner.run { context ->
                assertThat(context).doesNotHaveBean(Maskinportenklient::class.java)
            }
        }

        "Fails to autoconfigure if the required configuration properties is not provided" {
            contextRunner.withBean(VirksomhetSertifikater::class.java, { mockk<VirksomhetSertifikater>() })
                .run { context ->
                    assertThat(context).hasFailed()
                }
        }
    }

    private val contextRunner by lazy {
        ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MaskinportenAutoConfigure::class.java))
    }

    private val mockPrivateKey = object : PrivateKey {
        override fun getAlgorithm(): String = "RSA"

        override fun getFormat(): String = "format"

        override fun getEncoded(): ByteArray = Random.nextBytes(256)
    }

    private val mockCertificate = object : X509Certificate() {
        override fun toString(): String {
            TODO("Not yet implemented")
        }

        override fun getEncoded(): ByteArray = Random.nextBytes(256)

        override fun verify(key: PublicKey?) {
            TODO("Not yet implemented")
        }

        override fun verify(key: PublicKey?, sigProvider: String?) {
            TODO("Not yet implemented")
        }

        override fun getPublicKey(): PublicKey {
            TODO("Not yet implemented")
        }

        override fun hasUnsupportedCriticalExtension(): Boolean {
            TODO("Not yet implemented")
        }

        override fun getCriticalExtensionOIDs(): MutableSet<String> {
            TODO("Not yet implemented")
        }

        override fun getNonCriticalExtensionOIDs(): MutableSet<String> {
            TODO("Not yet implemented")
        }

        override fun getExtensionValue(oid: String?): ByteArray {
            TODO("Not yet implemented")
        }

        override fun checkValidity() {
            TODO("Not yet implemented")
        }

        override fun checkValidity(date: Date?) {
            TODO("Not yet implemented")
        }

        override fun getVersion(): Int {
            TODO("Not yet implemented")
        }

        override fun getSerialNumber(): BigInteger {
            TODO("Not yet implemented")
        }

        @Deprecated("Deprecated in Java")
        override fun getIssuerDN(): Principal {
            TODO("Not yet implemented")
        }

        @Deprecated("Deprecated in Java")
        override fun getSubjectDN(): Principal {
            TODO("Not yet implemented")
        }

        override fun getNotBefore(): Date {
            TODO("Not yet implemented")
        }

        override fun getNotAfter(): Date {
            TODO("Not yet implemented")
        }

        override fun getTBSCertificate(): ByteArray {
            TODO("Not yet implemented")
        }

        override fun getSignature(): ByteArray {
            TODO("Not yet implemented")
        }

        override fun getSigAlgName(): String {
            TODO("Not yet implemented")
        }

        override fun getSigAlgOID(): String {
            TODO("Not yet implemented")
        }

        override fun getSigAlgParams(): ByteArray {
            TODO("Not yet implemented")
        }

        override fun getIssuerUniqueID(): BooleanArray {
            TODO("Not yet implemented")
        }

        override fun getSubjectUniqueID(): BooleanArray {
            TODO("Not yet implemented")
        }

        override fun getKeyUsage(): BooleanArray {
            TODO("Not yet implemented")
        }

        override fun getBasicConstraints(): Int {
            TODO("Not yet implemented")
        }
    }

}
