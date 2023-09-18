package no.ks.fiks.maskinporten

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import java.security.cert.X509Certificate

interface JWSHeaderProvider {
    fun buildJWSHeader(): JWSHeader
}

class VirksomhetssertifikatJWSHeaderProvider(private val certificate: X509Certificate) : JWSHeaderProvider {
    private val jwsAlgorithm by lazy {
        when (certificate.sigAlgOID) {
            "1.2.840.113549.1.1.13" -> JWSAlgorithm.RS512
            "1.2.840.113549.1.1.12" -> JWSAlgorithm.RS384
            else -> JWSAlgorithm.RS256
        }
    }

    override fun buildJWSHeader() =
        JWSHeader.Builder(jwsAlgorithm)
            .x509CertChain(listOf(Base64.encode(certificate.encoded)))
            .build()

}

class AsymmetricKeyJWSHeaderProvider(private val keyId: String, private val signingAlgorithm: SigningAlgorithm) : JWSHeaderProvider {
    override fun buildJWSHeader() =
        JWSHeader.Builder(signingAlgorithm.toJwsAlgorithm())
            .keyID(keyId)
            .build()

    private fun SigningAlgorithm.toJwsAlgorithm() = when (this) {
        SigningAlgorithm.RS512 -> JWSAlgorithm.RS512
        SigningAlgorithm.RS384 -> JWSAlgorithm.RS384
        SigningAlgorithm.RS256 -> JWSAlgorithm.RS256
    }
}
