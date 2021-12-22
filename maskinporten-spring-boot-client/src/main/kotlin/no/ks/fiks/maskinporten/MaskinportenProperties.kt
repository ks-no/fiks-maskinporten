package no.ks.fiks.maskinporten

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import org.springframework.validation.annotation.Validated
import javax.validation.constraints.NotNull

internal const val DEFAULT_SECONDS_LEFT_BEFORE_EXPIRATION = 10

@ConstructorBinding
@ConfigurationProperties(prefix = "maskinporten")
@Validated
data class MaskinportenProperties(
    val audience: @NotNull String? = null,
    val tokenEndpoint: @NotNull String? = null,
    val issuer: @NotNull String? = null,
    val consumerOrg: String? = null,
    val numberOfSecondsLeftBeforeExpire: Int = DEFAULT_SECONDS_LEFT_BEFORE_EXPIRATION
) {
    fun toMaskinportenklientProperties(): MaskinportenklientProperties = MaskinportenklientProperties.builder()
        .numberOfSecondsLeftBeforeExpire(numberOfSecondsLeftBeforeExpire)
        .issuer(issuer ?: throw IllegalArgumentException(""""issuer" property can not be null"""))
        .audience(audience ?: throw IllegalArgumentException(""""audience" property can not be null"""))
        .tokenEndpoint(tokenEndpoint?: throw IllegalArgumentException(""""tokenEndpoint" property can not be null"""))
        .also {
            consumerOrg?.run { it.consumerOrg(this) }
        }
        .build()
}