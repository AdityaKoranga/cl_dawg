import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Milenage {
    private byte[] k;
    private byte[] op;
    private byte[] opc;

    public Milenage(byte[] k, byte[] op) {
        this.k = k;
        this.op = op;
        this.opc = computeOpc(k, op);
    }

    private byte[] computeOpc(byte[] k, byte[] op) {
        byte[] encrypted = aesEncrypt(k, op);
        byte[] opc = xor(encrypted, op);
        return opc;
    }

    private byte[] aesEncrypt(byte[] key, byte[] data) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("AES encryption failed", e);
        }
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public byte[] milenageF1(byte[] rand, byte[] sqn, byte[] amf) {
        byte[] temp = xor(rand, opc);
        byte[] encrypted = aesEncrypt(k, temp);
        byte[] result = xor(encrypted, sqn);
        result = xor(result, amf);
        return result;
    }

    public byte[][] milenageF2345(byte[] rand) {
        byte[] temp = xor(rand, opc);
        byte[] encrypted = aesEncrypt(k, temp);
        byte[] res = Arrays.copyOfRange(encrypted, 0, 8);
        byte[] ak = Arrays.copyOfRange(encrypted, 8, 14);
        byte[] ck = Arrays.copyOfRange(encrypted, 0, 16);
        byte[] ik = Arrays.copyOfRange(encrypted, 16, 32);
        return new byte[][]{res, ak, ck, ik};
    }

    public static void main(String[] args) {
        byte[] k = new byte[16];  // Example key
        byte[] op = new byte[16]; // Example OP
        byte[] rand = new byte[16]; // Example RAND
        byte[] sqn = new byte[6]; // Example SQN
        byte[] amf = new byte[2]; // Example AMF

        Milenage milenage = new Milenage(k, op);
        byte[] f1Result = milenage.milenageF1(rand, sqn, amf);
        byte[][] f2345Result = milenage.milenageF2345(rand);

        System.out.println("F1: " + Arrays.toString(f1Result));
        System.out.println("RES: " + Arrays.toString(f2345Result[0]));
        System.out.println("AK: " + Arrays.toString(f2345Result[1]));
        System.out.println("CK: " + Arrays.toString(f2345Result[2]));
        System.out.println("IK: " + Arrays.toString(f2345Result[3]));
    }
}