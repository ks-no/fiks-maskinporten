package no.ks.fiks.maskinporten

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.validation.annotation.Validated

@ConfigurationProperties(prefix = "maskinporten.private-key")
@Validated
data class PrivateKeyProperties(
    val pemFilePath: String)