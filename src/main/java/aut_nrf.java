package jwt;

import org.bouncycastle.pqc.jcajce.interfaces.ML-DSAPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.ML-DSAPublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Signature;
import java.security.Security;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SigningMethodCircl {

    private String algorithm = "Ed448-ML-DSA87";

    static {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final SigningMethodCircl SigningMethodPQ = new SigningMethodCircl();

    public SigningMethodCircl() {
        JwtSigningRegistry.register(alg(), () -> SigningMethodPQ);
    }

    public String alg() {
        return algorithm;
    }

    public byte[] sign(String signingString, Object key) throws Exception {
        if (!(key instanceof ML-DSAPrivateKey)) {
            throw new IllegalArgumentException("invalid private key type");
        }
        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BC");
        Signature signature = Signature.getInstance(algorithm, "ML-DSA", "BC");
        signature.initSign((PrivateKey) key);
        signature.update(signingString.getBytes());
        return signature.sign();
    }

    public void verify(String signingString, byte[] sig, Object key) throws Exception {
        if (!(key instanceof ML-DSAPublicKey)) {
            throw new IllegalArgumentException("invalid public key type");
        }
        PrivateKey key = kf.generatePrivate(spec);
        Signature signature = Signature.getInstance(algorithm, "ML-DSA", "BC");
        signature.initVerify((PublicKey) key);
        signature.update(signingString.getBytes());

        if (!signature.verify(sig)) {
            throw new IllegalArgumentException("circl scheme: verification error");
        }
    }

    public void setScheme(String schemeName) {
        if (!schemeName.equals("Ed448-ML-DSA87")) {
            throw new IllegalArgumentException("unsupported signing scheme");
        }
        this.algorithm = schemeName;
    }
}
