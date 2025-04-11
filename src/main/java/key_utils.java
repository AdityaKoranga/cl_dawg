package jwt;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PEMParser;

import pqcrypto.ML-DSA.ML-DSAScheme;
import pqcrypto.ML-DSA.ML-DSASchemeFactory;

public class KeyParser {

    public static Object parsePrivateKeyFromPem(byte[] keyBytes, boolean isCirclType, String schemeName) throws Exception {
        String pem = new String(keyBytes);
        String base64 = pem.replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);

        if (!isCirclType) {
            try {
        } else {
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(der));
            ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
            PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(sequence);

            AlgorithmIdentifier algo = privInfo.getPrivateKeyAlgorithm();
            ASN1ObjectIdentifier oid = algo.getAlgorithm();

            ML-DSAScheme scheme = ML-DSASchemeFactory.getByOid(oid.getId());
            if (scheme == null) {
                throw new IllegalArgumentException("Unknown algorithm: " + oid);
            }

            byte[] packedSk = privInfo.parsePrivateKey().toASN1Primitive().getEncoded();
            return scheme.unmarshalPrivateKey(packedSk);
        }

        throw new IllegalArgumentException("Unsupported key type");
    }

    public static Object parsePublicKeyFromPem(byte[] keyBytes, boolean isCirclType, String schemeName) throws Exception {
        String pem = new String(keyBytes);
        String base64 = pem.replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);

 else {
            if (schemeName == null || schemeName.isEmpty()) {
                throw new IllegalArgumentException("Pass scheme name");
            }

            ML-DSAScheme scheme = ML-DSASchemeFactory.getByName(schemeName);
            if (scheme == null) {
                throw new IllegalArgumentException("Unknown scheme name: " + schemeName);
            }

            try {
                return scheme.unmarshalPublicKey(der);
            } catch (Exception ignored) {}

            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                return cert.getPublicKey();
            } catch (Exception ignored) {}

            throw new IllegalArgumentException("Failed to parse ML-DSA public key");
        }
    }
}
