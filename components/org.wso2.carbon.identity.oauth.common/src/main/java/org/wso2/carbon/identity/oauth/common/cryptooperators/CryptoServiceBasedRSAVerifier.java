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
import com.nimbusds.jose.JWSVerifier;
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
 * Implementation of {@link JWSVerifier} based on Carbon Crypto Service.
 * Instances of this class provides JWT verification using Carbon Crypto Service.
 */
public class CryptoServiceBasedRSAVerifier implements JWSVerifier {

    private static Log log = LogFactory.getLog(CryptoServiceBasedRSAVerifier.class);

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    /**
     * Default constructor of {@link CryptoServiceBasedRSAVerifier}.
     *
     * @param cryptoContext : Context related to data to be verified.
     * @param jceProvider   : JCE Provider used for verification.
     */
    public CryptoServiceBasedRSAVerifier(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (CommonUtilDataHolder.getCryptoService() != null) {
            cryptoService = CommonUtilDataHolder.getCryptoService();
        }
    }

    /**
     * Verify a given signature with given data using Carbon Crypto Service.
     *
     * @param jwsHeader        : {@link JWSHeader}
     * @param dataToBeVerified : Data that needs to be verified.
     * @param signature        : Signature
     * @return true / false depending on the verification.
     * @throws JOSEException
     */
    @Override
    public boolean verify(JWSHeader jwsHeader, byte[] dataToBeVerified, Base64URL signature) throws JOSEException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Signing JWT token with header : %s", jwsHeader.toJSONObject().toJSONString()));
        }
        String algorithm = CryptoServiceBasedRSASSA.getSignVerifyAlgorithm(jwsHeader.getAlgorithm());
        try {
            return cryptoService.verifySignature(dataToBeVerified, signature.decode(), algorithm, jceProvider, cryptoContext);
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while verifying JWT signature using '%s' algorithm",
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
     * Returns the set of supported algorithms{@link JWSAlgorithm} by the CryptoServiceBasedRSAVerifier.
     *
     * @return Set of {@link JWSAlgorithm} supported.
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
