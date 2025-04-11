import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import org.bouncycastle.pqc.jcajce.interfaces.ML-DSAPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

public class JwtGenerator {

    public static void main(String[] args) throws Exception {
        String alg = "ML-DSA", "BC"; // Options: "P256", "ML-DSA", "BC"

        JWSSigner signer;
        JWSAlgorithm jwsAlg;
        KeyPair keyPair;

         if (alg.equals("ML-DSA", "BC")) {
            Security.addProvider(new BouncyCastlePQCProvider());

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
            keyGen.initialize(65); // Assuming 65 is ML-DSA-65
            keyPair = keyGen.generateKeyPair();

            jwsAlg = new JWSAlgorithm("ML-DSA-65");
            signer = new ML-DSASigner((ML-DSAPrivateKey) keyPair.getPrivate());

        } else {
            throw new IllegalArgumentException("Unknown algorithm: " + alg);
        }

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("foo", "bar")
            .issueTime(new Date())
            .expirationTime(new Date(System.currentTimeMillis() + 1000 * 60 * 10))
            .build();

        JWSHeader header = new JWSHeader.Builder(jwsAlg).type(JOSEObjectType.JWT).build();
        SignedJWT signedJWT = new SignedJWT(header, claims);

        signedJWT.sign(signer);

        String token = signedJWT.serialize();
        System.out.println(token);
    }
}
