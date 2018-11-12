package no.ks.fiks.maskinporten;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@ConfigurationProperties(prefix = "maskinporten")
@Validated
public class MaskinportenProperties {
    private String audience;
    private String tokenEndpoint;
    private String issuer;
    private int numberOfSecondsLeftBeforeExpire;
}
