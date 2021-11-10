package no.ks.fiks.maskinporten;

import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
import lombok.Value;

import java.util.Set;

@Value
@Builder
public class AccessTokenRequest {

    /**
     * Ønskede scopes for access token. Required.
     */
    @Singular
    @NonNull
    Set<String> scopes;

    /**
     * Organisasjonsnummer for organisasjon som token skal hentes på vegne av. Optional.
     */
    String consumerOrg;


    /**
     * Ønsket audience for access token. Optional.
     */
    String audience;
}
