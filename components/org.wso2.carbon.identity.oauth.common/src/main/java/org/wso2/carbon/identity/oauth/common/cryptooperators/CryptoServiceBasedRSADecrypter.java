/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.common.cryptooperators;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.crypto.api.HybridEncryptionOutput;
import org.wso2.carbon.identity.oauth.common.internal.CommonUtilDataHolder;

import java.nio.charset.Charset;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Set;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Implementation of {@link JWEDecrypter} based of Carbon Crypto Service.
 * Instances of this class provides JWT decryption using Carbon Crypto Service.
 */
public class CryptoServiceBasedRSADecrypter implements JWEDecrypter {

    private Log log = LogFactory.getLog(CryptoServiceBasedRSADecrypter.class);

    private CryptoContext cryptoContext;
    private String jceProvider;
    private CryptoService cryptoService;

    /**
     * Default constructor of {@link CryptoServiceBasedRSADecrypter}.
     *
     * @param cryptoContext : Context related to decryption data.
     * @param jceProvider   : JCE Provider used for decryption.
     */
    public CryptoServiceBasedRSADecrypter(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (CommonUtilDataHolder.getCryptoService() != null) {
            cryptoService = CommonUtilDataHolder.getCryptoService();
        }
    }

    /**
     * Decrypt a given data related to JWT using Carbon Crypto Service.
     *
     * @param jweHeader    : Header of JWT.
     * @param encryptedKey : Encrypted symmetric key used for data encryption.
     * @param iv           : Initialization vector parameter
     * @param cipherText   : Encrypted text
     * @param authTag      : Authentication tag related to cipher text.
     * @return decrypted data
     * @throws JOSEException
     */
    @Override
    public byte[] decrypt(JWEHeader jweHeader, Base64URL encryptedKey, Base64URL iv, Base64URL cipherText,
                          Base64URL authTag) throws JOSEException {

        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Decrypting JWT token with header : %s", jweHeader.toJSONObject().toJSONString()));
        }
        String asymmetricAlgorithm = CipherHelper.resolveAsymmetricAlgorithm(jweHeader.getAlgorithm());
        String symmetricAlgorithm = CipherHelper.resolveSymmetricAlgorithm(jweHeader.getEncryptionMethod());

        AlgorithmParameterSpec parameterSpec;
        if (symmetricAlgorithm.contains("GCM")) {
            parameterSpec = new GCMParameterSpec(128, iv.decode());
        } else {
            String errorMessage = String.format("Symmetric algorithm '%s' is not supported by '%s'",
                    symmetricAlgorithm, this.getClass().getName());
            throw new JOSEException(errorMessage);
        }

        byte[] aad = computeAAD(jweHeader);

        try {
            return DeflateHelper.applyDecompression(jweHeader,
                    cryptoService.hybridDecrypt(new HybridEncryptionOutput(cipherText.decode(), encryptedKey.decode(),
                                    aad, authTag.decode(), parameterSpec),
                            symmetricAlgorithm, asymmetricAlgorithm, jceProvider, cryptoContext));
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while hybrid decrypting JWT using " +
                    "symmetric algorithm '%s' and asymmetric algorithm '%s'.", symmetricAlgorithm, asymmetricAlgorithm);
            throw new JOSEException(errorMessage, e);
        } finally {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully decrypted the JWT token with header : %s",
                        jweHeader.toJSONObject().toJSONString()));
            }
        }
    }

    /**
     * Returns set of asymmetric algorithms {@link JWEAlgorithm} supported by {@link CryptoServiceBasedRSAEncrypter}.
     *
     * @return set of supported {@link JWEAlgorithm}
     */
    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {

        return CipherHelper.getSupportedAlgorithms();
    }

    /**
     * Returns set of symmetric algorithms {@link EncryptionMethod} supported by {@link CryptoServiceBasedRSAEncrypter}.
     *
     * @return set of {@link EncryptionMethod}.
     */
    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {

        return CipherHelper.getSupportedEncryptionMethods();
    }

    @Override
    public JWEJCAContext getJCAContext() {

        // This method is not required for this implementation.
        return null;
    }

    private byte[] computeAAD(JWEHeader header) {

        return header.toBase64URL().toString().getBytes(Charset.forName("ASCII"));
    }
}
