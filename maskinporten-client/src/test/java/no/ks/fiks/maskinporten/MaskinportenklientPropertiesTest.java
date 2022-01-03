package no.ks.fiks.maskinporten;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class MaskinportenklientPropertiesTest {

    @DisplayName("Kan bruker statisk builder() metode")
    @Test
    void builderTest() {
        final int timeoutMillis = 22;
        final String issuer = "issuer";
        final String audience = "audience";
        final String tokenEndpoint = "https//localhost/token";
        final MaskinportenklientProperties maskinportenklientProperties = MaskinportenklientProperties.builder()
                .timeoutMillis(timeoutMillis)
                .issuer(issuer)
                .audience(audience)
                .tokenEndpoint(tokenEndpoint)
                .build();
        assertThat(maskinportenklientProperties.getTimeoutMillis()).isEqualTo(timeoutMillis);
        assertThat(maskinportenklientProperties.getIssuer()).isEqualTo(issuer);
        assertThat(maskinportenklientProperties.getAudience()).isEqualTo(audience);
        assertThat(maskinportenklientProperties.getTokenEndpoint()).isEqualTo(tokenEndpoint);
    }
}
