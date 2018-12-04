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

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * This class is used to keep supported algorithms {@link JWSAlgorithm} by CryptoService based sign and verification.
 * Also this class is used for resolving {@link JWSAlgorithm} to Standard JCE naming.
 */
class CryptoServiceBasedRSASSA {

    private static final Set<JWSAlgorithm> algorithms = new LinkedHashSet<JWSAlgorithm>() {{
        add(JWSAlgorithm.RS256);
        add(JWSAlgorithm.RS384);
        add(JWSAlgorithm.RS512);
        add(JWSAlgorithm.PS256);
        add(JWSAlgorithm.PS384);
        add(JWSAlgorithm.PS512);
    }};

    private CryptoServiceBasedRSASSA() {

    }

    /**
     * Resolves standard JCE name for given {@link JWSAlgorithm}
     *
     * @param jwsAlgorithm ; {@link JWSAlgorithm} that needs to be resolved.
     * @return Standard JCE name for the given JWS algorithm.
     * @throws JOSEException
     */
    static String getSignVerifyAlgorithm(JWSAlgorithm jwsAlgorithm) throws JOSEException {

        if (jwsAlgorithm.equals(JWSAlgorithm.RS256)) {
            return "SHA256withRSA";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.RS384)) {
            return "SHA384withRSA";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.RS512)) {
            return "SHA512withRSA";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.PS256)) {
            return "SHA256withRSAandMGF1";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.PS384)) {
            return "SHA384withRSAandMGF1";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.PS512)) {
            return "SHA512withRSAandMGF1";
        } else {
            String errorMessage = String.format("Requested sign/verify '%s' algorithm is not supported.",
                    jwsAlgorithm.getName());
            throw new JOSEException(errorMessage);
        }
    }

    /**
     * Returns set of supported {@link JWSAlgorithm}.
     *
     * @return set of supported sign verify algorithms by the implementation.
     */
    static Set<JWSAlgorithm> getSupportedAlgorithms() {

        return algorithms;
    }
}
