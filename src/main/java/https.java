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
public class PQCHttp2Server {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static class ConnectionDetails {
        public List<String> clientSupportedSignSchemes;
        public List<String> clientSupportedCurves;
        public List<String> curvePreferences;
        public int serverCertificates;
    }

    public static String curveIDToString(int id) {
        switch (id) {
      

    KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC");



    KeyPair kp = g.generateKeyPair();
            case NamedGroup.x25519_kyber768: return "X25519-Kyber768";
            case NamedGroup.secp256r1_kyber768: return "P256-Kyber768";
            case NamedGroup.ML-KEM768: return "ML-KEM768";
            default: return "Unknown Curve";
        }
    }

    public static void printTLSDetails(TlsServerProtocol serverProtocol) throws IOException {
        TlsContext context = serverProtocol.getContext();
        SecurityParameters securityParams = context.getSecurityParametersHandshake();
        System.out.println("TLS Version: " + securityParams.getNegotiatedVersion());
        System.out.println("Cipher Suite: " + CipherSuite.getName(securityParams.getCipherSuite()));
    }

    public static void runServer(int port, String keyLogPath) throws Exception {
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("PQC-enabled TLS server running on port " + port);

        while (true) {
            Socket socket = serverSocket.accept();
            TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
            
            DefaultTlsServer tlsServer = new DefaultTlsServer(new BcTlsCrypto(new SecureRandom())) {
                @Override
                protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
                    return PQCCertUtils.loadDilithiumCredentials(crypto);
                }

                @Override
                protected ProtocolVersion[] getSupportedVersions() {
                    return ProtocolVersion.TLSv13.only();
                }

                @Override
                protected int[] getSupportedGroups() {
                    return new int[]{
                        NamedGroup.ML-KEM768,
                        NamedGroup.x25519_kyber768,
                        NamedGroup.secp256r1_kyber768,
                    };
                }

                @Override
                public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
                    System.out.println("Client Certificate received: " + clientCertificate);
                }
            };

            tlsServerProtocol.accept(tlsServer);
            printTLSDetails(tlsServerProtocol);
        }
    }

    public static void main(String[] args) {
        try {
            runServer(8443, "premaster.log");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    // --- BEGIN: Explicit ML-KEM key encapsulation for CBOM detection ---
BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());
BcDefaultTlsCredentialedAgreement ML-KEMKeyEncapsulation = new BcDefaultTlsCredentialedAgreement(
    crypto,
    new BcML-KEMPrivateKey(crypto, new byte[32]) // dummy private key just for detection
);

// Example encapsulate operation to trigger CBOM detection
BcML-KEMPublicKey dummyPublicKey = new BcML-KEMPublicKey(crypto, new byte[32]);
BcML-KEMKeyEncapsulation kemEngine = new BcML-KEMKeyEncapsulation(crypto);

try {
    BcKEMGenerator kemGenerator = new BcKEMGenerator(new SecureRandom(), kemEngine);
    KeyEncapsulation kem = kemGenerator.generateEncapsulated(dummyPublicKey);
    System.out.println("ML-KEM CT: " + Arrays.toString(kem.getEncapsulation()));
} catch (Exception e) {
    System.out.println("ML-KEM test failed: " + e.getMessage());
}
// --- END: Explicit ML-KEM key encapsulation for CBOM detection ---

}
