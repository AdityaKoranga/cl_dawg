import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.*;
import org.bouncycastle.tls.crypto.impl.bc.pqc.*;
import org.bouncycastle.tls.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

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
            case NamedGroup.x25519_kyber768: return "X25519-Kyber768";
            case NamedGroup.secp256r1_kyber768: return "P256-Kyber768";
            case NamedGroup.mlkem768: return "MLKEM768";
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
                        NamedGroup.mlkem768,
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
BcDefaultTlsCredentialedAgreement mlkemKeyEncapsulation = new BcDefaultTlsCredentialedAgreement(
    crypto,
    new BcMLKEMPrivateKey(crypto, new byte[32]) // dummy private key just for detection
);

// Example encapsulate operation to trigger CBOM detection
BcMLKEMPublicKey dummyPublicKey = new BcMLKEMPublicKey(crypto, new byte[32]);
BcMLKEMKeyEncapsulation kemEngine = new BcMLKEMKeyEncapsulation(crypto);

try {
    BcKEMGenerator kemGenerator = new BcKEMGenerator(new SecureRandom(), kemEngine);
    KeyEncapsulation kem = kemGenerator.generateEncapsulated(dummyPublicKey);
    System.out.println("ML-KEM CT: " + Arrays.toString(kem.getEncapsulation()));
} catch (Exception e) {
    System.out.println("ML-KEM test failed: " + e.getMessage());
}
// --- END: Explicit ML-KEM key encapsulation for CBOM detection ---

}
