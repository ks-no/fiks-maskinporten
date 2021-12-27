package no.ks.fiks.maskinporten;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;


public class AccessTokenRequestBuilderTest {

    @DisplayName("Tester at builder fungerer som forventet")
    @Test
    void builderTest() {
        final String scopeOne = "first";
        final String scopeTwo = "second";
        final String audience = "audience";
        final String consumerOrg = "999999999";
        final AccessTokenRequest accessTokenRequest = AccessTokenRequest.builder()
                .scope(scopeOne)
                .scope(scopeTwo)
                .audience(audience)
                .consumerOrg(consumerOrg)
                .build();
        assertThat(accessTokenRequest.getScopes()).containsExactly(scopeOne, scopeTwo);
        assertThat(accessTokenRequest.getAudience()).isEqualTo(audience);
        assertThat(accessTokenRequest.getConsumerOrg()).isEqualTo(consumerOrg);
    }

    @DisplayName("Tester at builder fungerer som forventet også når vi oppgir scopes som Set")
    @Test
    @SuppressWarnings("unchecked")
    void builderWitchScopeSet() {
        final String scopeOne = "first";
        final String scopeTwo = "second";
        final String audience = "audience";
        final String consumerOrg = "999999999";
        final AccessTokenRequest accessTokenRequest = AccessTokenRequest.builder()
                .scopes(new HashSet(Arrays.asList(scopeOne, scopeTwo)))
                .audience(audience)
                .consumerOrg(consumerOrg)
                .build();
        assertThat(accessTokenRequest.getScopes()).containsExactly(scopeOne, scopeTwo);
        assertThat(accessTokenRequest.getAudience()).isEqualTo(audience);
        assertThat(accessTokenRequest.getConsumerOrg()).isEqualTo(consumerOrg);
    }

}
