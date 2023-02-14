/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.keyidprovider;

import com.nimbusds.jose.JWSAlgorithm;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.security.cert.Certificate;

/**
 * This extension is to provide custom Key ID calculation logic.
 */
public interface KeyIDProvider {

    /**
     * Method to retrieve the Key ID.
     *
     * @param certificate        Signing Certificate.
     * @param signatureAlgorithm Signature Algorithm as a String.
     * @param tenantDomain       Tenant Domain.
     * @return String value of Key ID.
     * @throws IdentityOAuth2Exception When failed to generate Key ID properly.
     */
    public String getKeyId(Certificate certificate, JWSAlgorithm signatureAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception;

    /**
     * Method containing the Key ID calculation logic with certificate thumbprint using SHA-1 alg and
     * signature algorithm.
     * This method is added to support migration from versions below IS 5.10 as we have switched the hashing algorithm
     * from SHA-1 to SHA-256.
     *
     * @param certificate        Signing Certificate.
     * @param signatureAlgorithm Signature Algorithm as a String.
     * @param tenantDomain       Tenant Domain.
     * @return String value of Previous Key ID.
     * @throws IdentityOAuth2Exception When failed to generate Key ID properly.
     */
    default String getPreviousKeyId(Certificate certificate, JWSAlgorithm signatureAlgorithm, String tenantDomain)
            throws IdentityOAuth2Exception {

        return OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate) + "_" + signatureAlgorithm.toString();
    }
}
