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

package org.bouncycastle.jcacje.provider.test;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;


public class MLKEMTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKEM()
            throws Exception
    {
        // Receiver side
        KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC");

        g.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        KeyPair kp = g.generateKeyPair();
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("ML-KEM");
        KTSParameterSpec ktsSpec = null;
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();
        byte[] params = enc.params();

        // Receiver side
        KEM kemR = KEM.getInstance("ML-KEM");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsSpec);
        SecretKey secR = d.decapsulate(em);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    public void testBasicKEMAES()
            throws Exception
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("AES"));
        performKEM(kpg.generateKeyPair(),0, 16, "AES", new KEMParameterSpec("AES"));
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("AES-KWP"));

        try
        {
            performKEM(kpg.generateKeyPair(),0, 16, "AES-KWP", new KEMParameterSpec("AES"));
            fail();
        }
        catch (Exception ex)
        {
        }

        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, new SecureRandom());
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("AES"));



    }

    public void testBasicKEMCamellia()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768, new SecureRandom());

        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("ARIA"));
        performKEM(kpg.generateKeyPair(), new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEM(KeyPair kp, int from, int to, String algorithm, KTSParameterSpec ktsParameterSpec)
            throws Exception
    {
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("ML-KEM");
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate(from, to, algorithm);
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        // Receiver side
        KEM kemR = KEM.getInstance("ML-KEM");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(em, from, to, algorithm);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }

    private void performKEM(KeyPair kp, KTSParameterSpec ktsParameterSpec)
            throws Exception
    {
        PublicKey pkR = kp.getPublic();

        // Sender side
        KEM kemS = KEM.getInstance("ML-KEM");
        KEM.Encapsulator e = kemS.newEncapsulator(pkR, ktsParameterSpec, null);
        KEM.Encapsulated enc = e.encapsulate();
        SecretKey secS = enc.key();
        byte[] em = enc.encapsulation();

        // Receiver side
        KEM kemR = KEM.getInstance("ML-KEM");
        KEM.Decapsulator d = kemR.newDecapsulator(kp.getPrivate(), ktsParameterSpec);
        SecretKey secR = d.decapsulate(em);

        // secS and secR will be identical
        assertEquals(secS.getAlgorithm(), secR.getAlgorithm());
        assertTrue(Arrays.areEqual(secS.getEncoded(), secR.getEncoded()));
    }
}