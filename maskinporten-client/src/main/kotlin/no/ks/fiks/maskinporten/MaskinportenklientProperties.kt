package no.ks.fiks.maskinporten

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import java.time.Duration
import java.util.concurrent.TimeUnit

val DEFAULT_TIMEOUT = Duration.ofSeconds(10).toMillis().toInt()

data class MaskinportenklientProperties(

    /**
     * Verdi som brukes i "aud" feltet når vi ber om token
     */
    val audience: String? = null,

    /**
     * URL til Maskinporten endepunktet vi skal be om token fra
     */
    val tokenEndpoint: String,

    /**
     * Verdi som brukes for "iss" feltet (clientId) når vi ber om token
     */
    val issuer: String? = null,

    /**
     * Angir maksimalt antall sekunder før et token utløper at klienten kan gi tilbake cachet token
     */
    val numberOfSecondsLeftBeforeExpire: Int = 0,

    /**
     * Organisasjonsnummeret til organisasjon man opptrer på vegne av (krever at tilgang er gitt i AltInn)
     * Dersom dette er ikke er en fast verdi oppgir du orgnr per request i stedet
     */
    val consumerOrg: String? = null,

    /**
     * Setter request timeout i millisekunder for token request kallet. Dette gjelder bare dersom du ikke oppgir en verdi for providedHttpClient
     */
    val timeoutMillis: Int = DEFAULT_TIMEOUT,

    /**
     * Om du vil håndtere livssyklus for httpklienten selv kan du setted denne her. Du må da selv sørge for å lukke denne
     */
    val providedHttpClient: CloseableHttpClient? = null
) {

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
    private var providedHttpClient: CloseableHttpClient? = null

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

    fun providedHttpClient(providedHttpClient: CloseableHttpClient): MaskinportenklientPropertiesBuilder {
        this.providedHttpClient = providedHttpClient
        return this
    }

    fun build(): MaskinportenklientProperties = MaskinportenklientProperties(
        audience = audience,
        tokenEndpoint = tokenEndpoint ?: throw IllegalArgumentException("""The "tokenEndpoint" property can not be null"""),
        issuer = issuer,
        numberOfSecondsLeftBeforeExpire = numberOfSecondsLeftBeforeExpire,
        consumerOrg = consumerOrg,
        timeoutMillis = timeoutMillis,
        providedHttpClient = providedHttpClient
    )
}
