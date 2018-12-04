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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.identity.oauth.common.internal.CommonUtilDataHolder;

import java.util.Set;

/**
 * Implementation of {@link JWSSigner} based on Carbon Crypto Service.
 * Instances of this class provides JWT signing using Carbon Crypto Service.
 */
public class CryptoServiceBasedRSASigner implements JWSSigner {

    private static Log log = LogFactory.getLog(CryptoServiceBasedRSASigner.class);

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    /**
     * Default constructor of {@link CryptoServiceBasedRSASigner}.
     *
     * @param cryptoContext : Context related to data to be signed.
     * @param jceProvider   : JCE Provider used for signing.
     */
    public CryptoServiceBasedRSASigner(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (CommonUtilDataHolder.getCryptoService() != null) {
            cryptoService = CommonUtilDataHolder.getCryptoService();
        }
    }

    /**
     * Sign a given data related to JWT using  Carbon Crypto Service {@link CryptoService}.
     *
     * @param jwsHeader      : Header of the JWT.
     * @param dataToBeSigned : Data that needs to be signed.
     * @return {@link Base64URL} of the signature.
     * @throws JOSEException
     */
    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] dataToBeSigned) throws JOSEException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Signing JWT token with header : %s", jwsHeader.toJSONObject().toJSONString()));
        }
        String algorithm = CryptoServiceBasedRSASSA.getSignVerifyAlgorithm(jwsHeader.getAlgorithm());
        try {
            return Base64URL.encode(cryptoService.sign(dataToBeSigned, algorithm, jceProvider, cryptoContext));
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while signing JWT token using %s algorithm.",
                    algorithm);
            throw new JOSEException(errorMessage, e);
        } finally {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully signed JWT token with header : %s",
                        jwsHeader.toJSONObject().toJSONString()));
            }
        }
    }

    /**
     * Returns set of supported {@link JWSAlgorithm}.
     *
     * @return set of supported algorithms.
     */
    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {

        return CryptoServiceBasedRSASSA.getSupportedAlgorithms();
    }

    @Override
    public JCAContext getJCAContext() {

        // This method is not required for this implementation.
        return null;
    }
}
