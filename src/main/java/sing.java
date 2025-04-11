import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.pqc.jcajce.interfaces.ML-DSAPrivateKey;

import java.security.Signature;
import java.util.Collections;
import java.util.Set;

public class ML-DSASigner implements JWSSigner {

    private final ML-DSAPrivateKey privateKey;

    public ML-DSASigner(ML-DSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        try {
            Signature sig = Signature.getInstance("ML-DSA", "BC");
            sig.initSign(privateKey);
            sig.update(signingInput);
            byte[] signature = sig.sign();
            return Base64URL.encode(signature);
        } catch (Exception e) {
            throw new JOSEException("Signing failed", e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return Collections.singleton(new JWSAlgorithm("ML-DSA-65"));
    }
}
