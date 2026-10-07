package no.ks.fiks.maskinporten.error

/**
 * Generic exception for all non-sucessful Maskinporten token requests
 *
 * @property maskinportenError the response body for 4xx and 5xx responses. It is empty for other response codes, because their body can contain an access token
 */
open class MaskinportenTokenRequestException(message: String?, val statusCode: Int, val maskinportenError: String) :
    RuntimeException(message)