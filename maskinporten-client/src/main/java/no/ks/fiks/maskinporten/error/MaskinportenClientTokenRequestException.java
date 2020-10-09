package no.ks.fiks.maskinporten.error;

/**
 * Used for client errors i.e when the response status for a token request is in the 4xx range
 */
public class MaskinportenClientTokenRequestException extends MaskinportenTokenRequestException {

    public MaskinportenClientTokenRequestException(String message, int statusCode, String maskinportenError) {
        super(message, statusCode, maskinportenError);
    }
}
