package no.ks.fiks.maskinporten;

import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
import lombok.Value;

import java.util.Set;

@Value
@Builder
public class AccessTokenRequest {

    @Singular
    @NonNull
    Set<String> scopes;

    String consumerOrg;
    String audience;
}
