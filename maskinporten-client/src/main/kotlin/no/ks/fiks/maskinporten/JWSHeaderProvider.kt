package no.ks.fiks.maskinporten

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import java.security.cert.X509Certificate

interface JWSHeaderProvider {
    fun buildJWSHeader(): JWSHeader
}

class VirksomhetssertifikatJWSHeaderProvider(private val certificate: X509Certificate) : JWSHeaderProvider {
    override fun buildJWSHeader() =
        JWSHeader.Builder(JWSAlgorithm.RS256)
            .x509CertChain(listOf(Base64.encode(certificate.encoded)))
            .build()
}

class AsymmetricKeyJWSHeaderProvider(private val keyId: String) : JWSHeaderProvider {
    override fun buildJWSHeader() =
        JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(keyId)
            .build()
}
