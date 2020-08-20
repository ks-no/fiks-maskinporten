package no.ks.fiks.maskinporten;

import lombok.Builder;
import lombok.Data;

import java.util.concurrent.TimeUnit;

@Data
@Builder
public class MaskinportenklientProperties {
    public String audience;
    private String tokenEndpoint;
    private String issuer;
    private int numberOfSecondsLeftBeforeExpire;
    private String consumerOrg = null;
    @Builder.Default
    private int timeoutMillis = (int) TimeUnit.MINUTES.toMillis(1L);
}
