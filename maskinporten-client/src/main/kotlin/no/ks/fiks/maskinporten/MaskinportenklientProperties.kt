package no.ks.fiks.maskinporten

import java.util.concurrent.TimeUnit

val DEFAULT_TIMEOUT = TimeUnit.MINUTES.toMillis(1L).toInt()

data class MaskinportenklientProperties(
    val audience: String? = null,
    val tokenEndpoint: String,
    val issuer: String? = null,
    val numberOfSecondsLeftBeforeExpire: Int = 0,
    val consumerOrg: String? = null,
    val timeoutMillis: Int = DEFAULT_TIMEOUT) {

    companion object {
        @JvmStatic
        fun builder() = MaskinportenklientPropertiesBuilder()
    }
}

class MaskinportenklientPropertiesBuilder {
    private var audience: String? = null
    private var tokenEndpoint: String? = null
    private var issuer: String? = null
    private var numberOfSecondsLeftBeforeExpire = 0
    private var consumerOrg: String? = null
    private var timeoutMillis: Int = DEFAULT_TIMEOUT

    fun audience(audience: String): MaskinportenklientPropertiesBuilder {
        this.audience = audience
        return this
    }

    fun tokenEndpoint(tokenEndpoint: String): MaskinportenklientPropertiesBuilder {
        this.tokenEndpoint = tokenEndpoint
        return this
    }

    fun issuer(issuer: String): MaskinportenklientPropertiesBuilder {
        this.issuer = issuer
        return this
    }

    fun numberOfSecondsLeftBeforeExpire(numberOfSecondsLeftBeforeExpire: Int): MaskinportenklientPropertiesBuilder {
        this.numberOfSecondsLeftBeforeExpire = numberOfSecondsLeftBeforeExpire
        return this
    }

    fun consumerOrg(consumerOrg: String): MaskinportenklientPropertiesBuilder {
        this.consumerOrg = consumerOrg
        return this
    }

    fun timeoutMillis(timeoutMillis: Int): MaskinportenklientPropertiesBuilder {
        this.timeoutMillis = timeoutMillis
        return this
    }

    fun build(): MaskinportenklientProperties = MaskinportenklientProperties(
        audience = audience,
        tokenEndpoint = tokenEndpoint ?: throw IllegalArgumentException("""The "tokenEndpoint" property can not be null"""),
        issuer = issuer,
        numberOfSecondsLeftBeforeExpire = numberOfSecondsLeftBeforeExpire,
        consumerOrg = consumerOrg,
        timeoutMillis = timeoutMillis
    )
}
