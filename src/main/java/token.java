// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package internal;

import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.IOException;

import java.security.PrivateKey;
import java.security.Security;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class KeyParser {

    static {
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    public static Object parseKey(byte[] keyBytes) throws Exception {
        // Decode PEM if present
        byte[] rawKey = decodePem(keyBytes);
        Exception err = null;

        // PKCS#1 (outdated) -- skipped
        // (no logic here because we're omitting classical crypto)

        // PKCS#8 (general method)
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rawKey);
            KeyFactory kf = KeyFactory.getInstance("MLDSA", "BCPQC");
            PrivateKey key = kf.generatePrivate(spec);
            return key;
        } catch (Exception e) {
            err = e;
        }

        throw new IllegalArgumentException("invalid private key format: parse error: " + err.getMessage(), err);
    }

    private static byte[] decodePem(byte[] input) throws IOException {
        try (PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(input)))) {
            PemObject pemObject = reader.readPemObject();
            if (pemObject != null) {
                return pemObject.getContent();
            }
        }
        return input;
    }
}
