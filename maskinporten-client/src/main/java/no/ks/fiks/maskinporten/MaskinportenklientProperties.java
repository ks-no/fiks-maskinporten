package no.ks.fiks.maskinporten;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MaskinportenklientProperties {
    public String audience;
    private String privateKeyAlias;
    private char[] privateKeyPassword;
    private String tokenEndpoint;
    private String issuer;
    private int numberOfSecondsLeftBeforeExpire;
}
