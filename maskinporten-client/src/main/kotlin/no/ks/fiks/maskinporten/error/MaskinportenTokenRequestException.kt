package no.ks.fiks.maskinporten.error;

/**
 * Generic exception for all non-sucessful Maskinporten token requests
 */
public class MaskinportenTokenRequestException extends RuntimeException {

    private final int statusCode;
    private final String maskinportenError;

    public MaskinportenTokenRequestException(String message, int statusCode, String maskinportenError) {
        super(message);
        this.statusCode = statusCode;
        this.maskinportenError = maskinportenError;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getMaskinportenError() {
        return maskinportenError;
    }
}
