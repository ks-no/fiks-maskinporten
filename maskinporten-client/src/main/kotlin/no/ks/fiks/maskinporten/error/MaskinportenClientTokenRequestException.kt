package no.ks.fiks.maskinporten.error

/**
 * Used for client errors i.e when the response status for a token request is in the 4xx range
 */
class MaskinportenClientTokenRequestException(message: String?, statusCode: Int, maskinportenError: String) :
    MaskinportenTokenRequestException(message, statusCode, maskinportenError)