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
     * Ønsket audience for access token. Optional.
     */
    val audience: String?) {

    companion object {
        @JvmStatic
        fun builder() = AccessTokenRequestBuilder()
    }
}

class AccessTokenRequestBuilder {

    private var scopes: Set<String> = emptySet()

    private var consumerOrg: String? = null

    private var audience: String? = null

    fun addScope(scope: String): AccessTokenRequestBuilder {
        this.scopes += scope
        return this
    }

    fun scopes(scopes: Set<String>): AccessTokenRequestBuilder {
        this.scopes = scopes.toSet()
        return this
    }

    fun audience(audience: String): AccessTokenRequestBuilder {
        this.audience = audience
        return this
    }

    fun consumerOrg(consumerOrg: String): AccessTokenRequestBuilder {
        this.consumerOrg = consumerOrg
        return this
    }

    fun build(): AccessTokenRequest = AccessTokenRequest(
        scopes = this.scopes.toSet(),
        audience = this.audience,
        consumerOrg = this.consumerOrg
    )

}