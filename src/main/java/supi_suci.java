package org.free5gc.pqcrypto;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class SuciDecryptor {

    public static class MLKEM {
        public static byte[][] decapsulate(byte[] ciphertext, byte[] sk) {
            // Stub: Simulate ML-KEM decapsulation
            byte[] sharedSecret = new byte[32];
            new SecureRandom().nextBytes(sharedSecret);
            return new byte[][]{sharedSecret};
        }
    }

    public static byte[] shake256(byte[] input, int outputLen) {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(input, 0, input.length);
        byte[] output = new byte[outputLen];
        shake.doFinal(output, 0, outputLen);
        return output;
    }

    public static byte[] hkdfShake256(byte[] ikm, byte[] salt, byte[] info, int length) {
        byte[] prk = shake256(concat(salt, ikm), 32);
        return shake256(concat(prk, info), length);
    }

    public static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) throws Exception {
        AEADParameters parameters = new AEADParameters(new KeyParameter(key), 128, nonce, aad);
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(false, parameters);

        byte[] output = new byte[cipher.getOutputSize(ciphertext.length)];
        int len = cipher.processBytes(ciphertext, 0, ciphertext.length, output, 0);
        cipher.doFinal(output, len);
        return output;
    }

    public static byte[] hmacShaShake256(byte[] key, byte[] message) {
        SHAKEDigest digest = new SHAKEDigest(256);
        HMac hmac = new HMac(digest);
        hmac.init(new KeyParameter(key));
        hmac.update(message, 0, message.length);
        byte[] out = new byte[32];
        hmac.doFinal(out, 0);
        return out;
    }

    public static byte[] decryptSuci(byte[] encryptedData, byte[] kemCiphertext, byte[] kemPrivateKey) throws Exception {
        // Step 1: Decapsulate ML-KEM
        byte[] sharedSecret = MLKEM.decapsulate(kemCiphertext, kemPrivateKey)[0];

        // Step 2: Derive keys using HKDF-like function with SHAKE256
        byte[] salt = "suci-salt".getBytes(StandardCharsets.UTF_8);
        byte[] info = "suci-decoder-context".getBytes(StandardCharsets.UTF_8);
        byte[] derivedKey = hkdfShake256(sharedSecret, salt, info, 32);

        // Step 3: Assume AAD and nonce are prepended (for demonstration)
        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, 12);
        byte[] aad = Arrays.copyOfRange(encryptedData, 12, 24);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, 24, encryptedData.length);

        // Step 4: Decrypt using AES-GCM
        return aesGcmDecrypt(derivedKey, nonce, ciphertext, aad);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    public static void main(String[] args) throws Exception {
        byte[] kemCiphertext = Hex.decode("deadbeefcafebabe");
        byte[] kemPrivateKey = Hex.decode("00112233445566778899aabbccddeeff");
        byte[] encryptedData = new byte[64];
        new SecureRandom().nextBytes(encryptedData);

        byte[] supi = decryptSuci(encryptedData, kemCiphertext, kemPrivateKey);
        System.out.println("SUPI: " + Hex.toHexString(supi));
    }
}
