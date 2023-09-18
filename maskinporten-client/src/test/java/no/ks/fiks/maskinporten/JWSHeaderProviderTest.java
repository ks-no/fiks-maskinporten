package no.ks.fiks.maskinporten;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JWSHeaderProviderTest {

    @Test
    @DisplayName("Test that virksomhetssertifikat header is correctly built")
    void testVirksomhetssertifikatHeader() throws CertificateEncodingException {
        X509Certificate cert = mock(X509Certificate.class);
        String encoded = UUID.randomUUID().toString();
        when(cert.getEncoded()).thenReturn(encoded.getBytes(StandardCharsets.UTF_8));

        JWSHeader header = new VirksomhetssertifikatJWSHeaderProvider(cert).buildJWSHeader();

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(header.getX509CertChain().size()).isEqualTo(1);
        assertThat(header.getX509CertChain().get(0).decodeToString()).isEqualTo(encoded);
    }

    @Test
    @DisplayName("Test that asymmetric key header is correctly built")
    void testAsymmetricKeyHeader() {
        String keyId = UUID.randomUUID().toString();
        JWSHeader header = new AsymmetricKeyJWSHeaderProvider(keyId, SigningAlgorithm.RS256).buildJWSHeader();

        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(header.getKeyID()).isEqualTo(keyId);
    }
}
