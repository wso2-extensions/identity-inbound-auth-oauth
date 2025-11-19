package org.wso2.carbon.identity.oauth2.crypto.impl;

import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.AlgorithmParametersHelper;
import com.nimbusds.jose.crypto.impl.CipherHelper;
import net.jcip.annotations.ThreadSafe;


/**
 * RSAES OAEP (SHA-384) methods for Content Encryption Key (CEK) encryption and
 * decryption. Uses the BouncyCastle.org provider. This class is thread-safe
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version 2017-11-27
 */
@ThreadSafe
public class RSA_OAEP_384 {


    /**
     * The JCA algorithm name for RSA-OAEP-384.
     */
    private static final String RSA_OEAP_384_JCA_ALG = "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";


    /**
     * Encrypts the specified Content Encryption Key (CEK).
     *
     * @param pub      The public RSA key. Must not be {@code null}.
     * @param cek      The Content Encryption Key (CEK) to encrypt. Must
     *                 not be {@code null}.
     * @param provider The JCA provider, or {@code null} to use the default
     *                 one.
     *
     * @return The encrypted Content Encryption Key (CEK).
     *
     * @throws JOSEException If encryption failed.
     */
    public static byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek, final Provider provider)
            throws JOSEException {

        try {
            AlgorithmParameters algp = AlgorithmParametersHelper.getInstance("OAEP", provider);
            AlgorithmParameterSpec paramSpec = new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT);
            algp.init(paramSpec);
            Cipher cipher = CipherHelper.getInstance(RSA_OEAP_384_JCA_ALG, provider);
            cipher.init(Cipher.ENCRYPT_MODE, pub, algp);
            return cipher.doFinal(cek.getEncoded());

        } catch (IllegalBlockSizeException e) {
            throw new JOSEException("RSA block size exception: The RSA key is too short, try a longer one", e);
        } catch (Exception e) {
            // java.security.NoSuchAlgorithmException
            // java.security.NoSuchPaddingException
            // java.security.InvalidKeyException
            // javax.crypto.BadPaddingException
            throw new JOSEException(e.getMessage(), e);
        }
    }


    /**
     * Decrypts the specified encrypted Content Encryption Key (CEK).
     *
     * @param priv         The private RSA key. Must not be {@code null}.
     * @param encryptedCEK The encrypted Content Encryption Key (CEK) to
     *                     decrypt. Must not be {@code null}.
     * @param provider     The JCA provider, or {@code null} to use the
     *                     default one.
     *
     * @return The decrypted Content Encryption Key (CEK).
     *
     * @throws JOSEException If decryption failed.
     */
    public static SecretKey decryptCEK(final PrivateKey priv,
                                       final byte[] encryptedCEK, final Provider provider)
            throws JOSEException {

        try {
            AlgorithmParameters algp = AlgorithmParametersHelper.getInstance("OAEP", provider);
            AlgorithmParameterSpec paramSpec = new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, PSource.PSpecified.DEFAULT);
            algp.init(paramSpec);
            Cipher cipher = CipherHelper.getInstance(RSA_OEAP_384_JCA_ALG, provider);
            cipher.init(Cipher.DECRYPT_MODE, priv, algp);
            return new SecretKeySpec(cipher.doFinal(encryptedCEK), "AES");

        } catch (Exception e) {
            // java.security.NoSuchAlgorithmException
            // java.security.NoSuchPaddingException
            // java.security.InvalidKeyException
            // javax.crypto.IllegalBlockSizeException
            // javax.crypto.BadPaddingException
            throw new JOSEException(e.getMessage(), e);
        }
    }


    /**
     * Prevents public instantiation.
     */
    private RSA_OAEP_384() { }
}
