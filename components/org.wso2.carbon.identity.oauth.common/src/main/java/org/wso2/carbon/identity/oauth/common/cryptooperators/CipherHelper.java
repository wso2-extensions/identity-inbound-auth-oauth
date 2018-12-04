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

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * This class is used to keep supported encryption and decryption mechanisms.
 * Also this class is used for resolving JWE mechanisms to Standard JCE naming.
 */
class CipherHelper {

    private static final Set<JWEAlgorithm> algorithms = new LinkedHashSet<JWEAlgorithm>() {{
        add(JWEAlgorithm.RSA1_5);
        add(JWEAlgorithm.RSA_OAEP);
        add(JWEAlgorithm.RSA_OAEP_256);
    }};

    private static final Set<EncryptionMethod> encryptionMethods = new LinkedHashSet<EncryptionMethod>() {{
        add(EncryptionMethod.A128GCM);
        add(EncryptionMethod.A192GCM);
        add(EncryptionMethod.A256GCM);
    }};

    /**
     * Returns supported algorithms.
     *
     * @return Set of {@link JWEAlgorithm}
     */
    static Set<JWEAlgorithm> getSupportedAlgorithms() {

        return algorithms;
    }

    /**
     * Returns a set of supported symmetric encryption methods.
     *
     * @return Set of {@link EncryptionMethod}
     */
    static Set<EncryptionMethod> getSupportedEncryptionMethods() {

        return encryptionMethods;
    }

    /**
     * Resolves standard JCE name for given {@link JWEAlgorithm}
     *
     * @param encryptionAlgorithm : Algorithm that needs to be resolved.
     * @return Standard JCE name for the given algorithm.
     * @throws JOSEException
     */
    static String resolveAsymmetricAlgorithm(JWEAlgorithm encryptionAlgorithm) throws JOSEException {

        if (encryptionAlgorithm.equals(JWEAlgorithm.RSA1_5)) {
            return "RSA/ECB/PKCS1Padding";
        } else if (encryptionAlgorithm.equals(JWEAlgorithm.RSA_OAEP)) {
            return "RSA/ECB/OAEPwithSHA1andMGF1Padding";
        } else if (encryptionAlgorithm.equals(JWEAlgorithm.RSA_OAEP_256)) {
            return "RSA/ECB/OAEPwithSHA256andMGF1Padding";
        } else {
            String errorMessage = String.format("Requested asymmetric algorithm '%s' is not supported.",
                    encryptionAlgorithm.getName());
            throw new JOSEException(errorMessage);
        }
    }

    /**
     * Resolves standard JCE naming for given {@link EncryptionMethod}.
     *
     * @param encryptionMethod : Encryption method to resolve the standard JCE name.
     * @return Standard JCE name for the given encryption method.
     * @throws JOSEException
     */
    static String resolveSymmetricAlgorithm(EncryptionMethod encryptionMethod) throws JOSEException {

        if (encryptionMethod.equals(EncryptionMethod.A128GCM)) {
            return "AES_128/GCM/NoPadding";
        } else if (encryptionMethod.equals(EncryptionMethod.A192GCM)) {
            return "AES_192/GCM/NoPadding";
        } else if (encryptionMethod.equals(EncryptionMethod.A256GCM)) {
            return "AES_256/GCM/NoPadding";
        } else {
            String errorMessage = String.format("Requested symmetric algorithm '%s' is not supported by " +
                    "Crypto Service based RSA provider.", encryptionMethod.getName());
            throw new JOSEException(errorMessage);
        }
    }
}
