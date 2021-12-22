package no.ks.fiks.maskinporten.error

/**
 * Generic exception for all non-sucessful Maskinporten token requests
 */
open class MaskinportenTokenRequestException(message: String?, val statusCode: Int, val maskinportenError: String) :
    RuntimeException(message)