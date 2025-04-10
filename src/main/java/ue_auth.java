import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class EapAuthHandler {

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SHA_256 = "SHA-256";

    public static byte[] computeHMAC(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, HMAC_SHA256);
            mac.init(secretKeySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Error computing HMAC", e);
        }
    }

    public static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static boolean validateHMAC(byte[] expected, byte[] key, byte[] data) {
        byte[] calculatedHmac = computeHMAC(key, data);
        return Arrays.equals(expected, calculatedHmac);
    }

    public static void main(String[] args) {
        // Example usage
        String message = "EAP-AKA Authentication";
        String secret = "SuperSecretKey";

        byte[] hmacResult = computeHMAC(secret.getBytes(StandardCharsets.UTF_8),
                message.getBytes(StandardCharsets.UTF_8));

        System.out.println("Computed HMAC: " + bytesToHex(hmacResult));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}