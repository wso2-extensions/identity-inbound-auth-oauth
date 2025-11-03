package org.wso2.carbon.identity.oauth2.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSA_OAEP_384;
import org.wso2.carbon.identity.oauth2.crypto.impl.RSA_OAEP_512;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPublicKey;

public class JWEEncryptor extends RSAEncrypter {

    /**
     * The externally supplied AES content encryption key (CEK) to use,
     * {@code null} to generate a CEK for each JWE.
     */
    private final SecretKey contentEncryptionKey;

    public JWEEncryptor(RSAPublicKey publicKey) {

        super(publicKey);
        this.contentEncryptionKey = null;
    }

    public JWEEncryptor(final RSAPublicKey publicKey, final SecretKey contentEncryptionKey) {

        super(publicKey, contentEncryptionKey);
        this.contentEncryptionKey = contentEncryptionKey;
    }

    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
            throws JOSEException {

        final com.nimbusds.jose.JWEAlgorithm alg = header.getAlgorithm();

        if (!alg.equals(JWEAlgorithm.RSA_OAEP_384) || !alg.equals(JWEAlgorithm.RSA_OAEP_512)) {
            return super.encrypt(header, clearText);
        }

        final EncryptionMethod enc = header.getEncryptionMethod();

        // Generate and encrypt the CEK according to the enc method
        final SecretKey cek;
        if (contentEncryptionKey != null) {
            // Use externally supplied CEK
            cek = contentEncryptionKey;
        } else {
            // Generate and encrypt the CEK according to the enc method
            cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());
        }

        final Base64URL encryptedKey; // The second JWE part

        if (alg.equals(JWEAlgorithm.RSA_OAEP_384)) {
            encryptedKey = Base64URL.encode(RSA_OAEP_384.encryptCEK(getPublicKey(), cek, getJCAContext().getKeyEncryptionProvider()));
        } else {
            encryptedKey = Base64URL.encode(RSA_OAEP_512.encryptCEK(getPublicKey(), cek, getJCAContext().getKeyEncryptionProvider()));
        }

        return ContentCryptoProvider.encrypt(header, clearText, cek, encryptedKey, getJCAContext());
    }
}
