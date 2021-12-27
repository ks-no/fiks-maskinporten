package no.ks.fiks.maskinporten

data class AccessTokenRequest(
    /**
     * Ønskede scopes for access token. Required.
     */
    val scopes: Set<String>,

    /**
     * Organisasjonsnummer for organisasjon som token skal hentes på vegne av. Optional.
     *
     * Bruk av dette krever at organisasjonen har delegert tilgangen i Altinn. Mer informasjon finnes på https://docs.digdir.no/maskinporten_func_delegering.html.
     */
    val consumerOrg: String? = null,

    /**
     * Ønsket audience for access token. Valgfritt.
     */
    val audience: String?) {

    companion object {
        /**
         * Oppretter en builder som skal gjøre det lettere å bygge AccessTokenRequest fra Java
         */
        @JvmStatic
        fun builder() = AccessTokenRequestBuilder()
    }
}

/**
 * Builder som gjør det lettere for klienter implementert i Java å bygge en AccessTokenRequest
 */
class AccessTokenRequestBuilder {

    private var scopes: Set<String> = emptySet()

    private var consumerOrg: String? = null

    private var audience: String? = null

    /**
     * Legger til et scope som skal brukes i forespørsel mot Maskinporten. Minst et scope må oppgies
     */
    fun scope(scope: String): AccessTokenRequestBuilder {
        this.scopes += scope
        return this
    }

    /**
     * Legger til et set med scopes som skal brukes i forespørsel mot Maskinporten. Minst et scope må oppgies
     */
    fun scopes(scopes: java.util.Set<String>): AccessTokenRequestBuilder {
        this.scopes = scopes.toSet()
        return this
    }

    /**
     * Legger til verdi som skal brukes i "aud" feltet i forespørsel mot Maskinporten. Valgfritt
     */
    fun audience(audience: String): AccessTokenRequestBuilder {
        this.audience = audience
        return this
    }

    /**
     * Brukes til forespørsler der man ønsker å få generert et token på vegne av en annen organisasjon.
     */
    fun consumerOrg(consumerOrg: String): AccessTokenRequestBuilder {
        this.consumerOrg = consumerOrg
        return this
    }

    /**
     * Bygger forespørselsobjekt
     */
    fun build(): AccessTokenRequest = AccessTokenRequest(
        scopes = scopes.toSet(),
        audience = this.audience,
        consumerOrg = this.consumerOrg
    )

}