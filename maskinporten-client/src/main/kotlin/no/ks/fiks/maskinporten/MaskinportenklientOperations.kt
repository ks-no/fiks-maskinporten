package no.ks.fiks.maskinporten

interface MaskinportenklientOperations {
    /**
     * Henter access token med spesifiserte scopes fra Maskinporten.
     *
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    fun getAccessToken(scopes: Collection<String>): String?

    /**
     * Henter access token med spesifiserte scopes fra Maskinporten.
     *
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    fun getAccessToken(vararg scopes: String): String?

    /**
     * Henter access token med spesifiserte scopes på vegne av en annen organisasjon fra Maskinporten.
     * Bruk av dette krever at organisasjonen har delegert tilgangen i Altinn. Mer informasjon finnes på https://docs.digdir.no/maskinporten_func_delegering.html.
     *
     * @param consumerOrg Organisasjonsnummer for organisasjon token skal hentes på vegne av
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    fun getDelegatedAccessToken(consumerOrg: String, scopes: Collection<String>): String?

    /**
     * Henter access token med spesifiserte scopes på vegne av en annen organisasjon fra Maskinporten.
     * Bruk av dette krever at organisasjonen har delegert tilgangen i Altinn. Mer informasjon finnes på https://docs.digdir.no/maskinporten_func_delegering.html.
     *
     * @param consumerOrg Organisasjonsnummer for organisasjon token skal hentes på vegne av
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    fun getDelegatedAccessToken(consumerOrg: String, vararg scopes: String): String?

    /**
     * Henter access token med spesifiserte scopes og audience fra Maskinporten.
     *
     * @param audience Ønsket audience for access token
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated(
        "Bruk {@link #getAccessToken(AccessTokenRequest)}"
    )
    fun getAccessTokenWithAudience(audience: String, scopes: Collection<String>): String?

    /**
     * Henter access token med spesifiserte scopes og audience fra Maskinporten.
     *
     * @param audience Ønsket audience for access token
     * @param scopes Forespurte scopes for access token
     * @return Access token hentet fra Maskinporten
     */
    @Deprecated(
        """Bruk {@link #getAccessToken(AccessTokenRequest)}
     
      """
    )
    fun getAccessTokenWithAudience(audience: String, vararg scopes: String): String?

    /**
     * Henter access token fra Maskinporten.
     *
     * @param request Request for access token
     * @return Access token hentet fra Maskinporten
     */
    fun getAccessToken(request: AccessTokenRequest): String?
}