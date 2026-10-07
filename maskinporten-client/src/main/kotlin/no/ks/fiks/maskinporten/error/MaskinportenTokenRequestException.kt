package no.ks.fiks.maskinporten.error

/**
 * Generic exception for all non-sucessful Maskinporten token requests
 *
 * @property maskinportenError the response body of a 4xx or 5xx response. For other response codes it is empty, because the body can contain an access token
 */
open class MaskinportenTokenRequestException(message: String?, val statusCode: Int, val maskinportenError: String) :
    RuntimeException(message)