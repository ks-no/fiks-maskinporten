package no.ks.fiks.maskinporten.error

class MaskinportenTokenTemporarilyUnavailableException(message: String?, statusCode: Int, maskinportenError: String) : MaskinportenTokenRequestException(message, statusCode, maskinportenError)