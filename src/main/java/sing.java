import com.nimbusds.jose.*;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.pqc.jcajce.interfaces.MLDSAPrivateKey;

import java.security.Signature;
import java.util.Collections;
import java.util.Set;

public class MLDsaSigner implements JWSSigner {

    private final MLDSAPrivateKey privateKey;

    public MLDsaSigner(MLDSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        try {
            Signature sig = Signature.getInstance("MLDSA", "BCPQC");
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
        return Collections.singleton(new JWSAlgorithm("MLDSA-65"));
    }
}
