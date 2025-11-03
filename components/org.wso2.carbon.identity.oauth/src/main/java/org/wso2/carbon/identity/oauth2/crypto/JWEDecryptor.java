package org.wso2.carbon.identity.oauth2.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSA_OAEP_384;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSA_OAEP_512;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Set;

public class JWEDecryptor extends RSADecrypter {

    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    public JWEDecryptor(PrivateKey privateKey) throws JOSEException {

        super(privateKey);
    }

    @Override
    public byte[] decrypt(final JWEHeader header, final Base64URL encryptedKey,
                          final Base64URL iv,
                          final Base64URL cipherText,
                          final Base64URL authTag)
            throws JOSEException {

        // Validate required JWE parts
        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        critPolicy.ensureHeaderPasses(header);


        // Derive the content encryption key
        com.nimbusds.jose.JWEAlgorithm alg = header.getAlgorithm();

        if (!alg.equals(JWEAlgorithm.RSA_OAEP_384) || !alg.equals(JWEAlgorithm.RSA_OAEP_512)) {
            return super.decrypt(header, encryptedKey, iv, cipherText, authTag);
        }

        SecretKey cek;

        if (alg.equals(JWEAlgorithm.RSA_OAEP_384)) {
            cek = RSA_OAEP_384.decryptCEK(getPrivateKey(), encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());
        } else {
            cek = RSA_OAEP_512.decryptCEK(getPrivateKey(), encryptedKey.decode(), getJCAContext().getKeyEncryptionProvider());
        }

        return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
    }
}
