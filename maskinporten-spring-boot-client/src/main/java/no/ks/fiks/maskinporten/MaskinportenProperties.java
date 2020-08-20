package no.ks.fiks.maskinporten;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;

@Data
@ConfigurationProperties(prefix = "maskinporten")
@Validated
public class MaskinportenProperties {
    @NotNull private String audience;
    @NotNull private String tokenEndpoint;
    @NotNull private String issuer;
    private String consumerOrg = null;
    private int numberOfSecondsLeftBeforeExpire = 10;
}
