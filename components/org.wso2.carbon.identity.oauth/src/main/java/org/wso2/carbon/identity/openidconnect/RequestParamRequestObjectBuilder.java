/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;

import static org.apache.commons.lang.StringUtils.isEmpty;
import static org.wso2.carbon.identity.openidconnect.model.Constants.JWT_PART_DELIMITER;
import static org.wso2.carbon.identity.openidconnect.model.Constants.NUMBER_OF_PARTS_IN_JWE;
import static org.wso2.carbon.identity.openidconnect.model.Constants.NUMBER_OF_PARTS_IN_JWS;

/**
 * This class is used to build request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */
public class RequestParamRequestObjectBuilder implements RequestObjectBuilder {

    private static Log log = LogFactory.getLog(RequestParamRequestObjectBuilder.class);

    /**
     * Builds request object which comes as the value of the request query parameter of OIDC authorization request
     *
     * @param requestObjectParam request object
     * @throws RequestObjectException
     */
    @Override
    public void buildRequestObject(String requestObjectParam, OAuth2Parameters oAuth2Parameters,
                                   RequestObject requestObjectInstance) throws RequestObjectException {
      
        //Making a copy of requestObjectParam to prevent editing initial reference
        String requestObjectParamValue = requestObjectParam;
        if (isEncrypted(requestObjectParamValue)) {
            requestObjectParamValue = decrypt(requestObjectParamValue, oAuth2Parameters);
        }
        setRequestObjectValues(requestObjectParamValue, requestObjectInstance);
    }

    /**
     * Decrypt the request object.
     *
     * @param requestObject    requestObject
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public String decrypt(String requestObject, OAuth2Parameters oAuth2Parameters) throws RequestObjectException {

        EncryptedJWT encryptedJWT;
        try {
            encryptedJWT = EncryptedJWT.parse(requestObject);
            RSAPrivateKey rsaPrivateKey = getRsaPrivateKey(oAuth2Parameters);
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);
            encryptedJWT.decrypt(decrypter);

            JWEObject jweObject = JWEObject.parse(requestObject);
            jweObject.decrypt(decrypter);

            if (jweObject != null && jweObject.getPayload() != null && jweObject.getPayload().toString()
                    .split(JWT_PART_DELIMITER).length == NUMBER_OF_PARTS_IN_JWS) {
                return jweObject.getPayload().toString();
            } else {
                return new PlainJWT((JWTClaimsSet) encryptedJWT.getJWTClaimsSet()).serialize();
            }

        } catch (JOSEException | IdentityOAuth2Exception | java.text.ParseException e) {
            String errorMessage = "Failed to decrypt request object.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, errorMessage);
        }
    }

    protected boolean isEncrypted(String requestObject) {
        return requestObject.split(JWT_PART_DELIMITER).length == NUMBER_OF_PARTS_IN_JWE;
    }

    protected RSAPrivateKey getRsaPrivateKey(OAuth2Parameters oAuth2Parameters) throws IdentityOAuth2Exception {
        String tenantDomain = getTenantDomainForDecryption(oAuth2Parameters);
        int tenantId = OAuth2Util.getTenantId(tenantDomain);
        Key key = OAuth2Util.getPrivateKey(tenantDomain, tenantId);
        return (RSAPrivateKey) key;
    }

    /**
     * Get tenant domain from oAuth2Parameters.
     *
     * @param oAuth2Parameters oAuth2Parameters
     * @return Tenant domain
     */
    private String getTenantDomainForDecryption(OAuth2Parameters oAuth2Parameters) {
        if (StringUtils.isNotEmpty(oAuth2Parameters.getTenantDomain())) {
            return oAuth2Parameters.getTenantDomain();
        }
        return MultitenantConstants.SUPER_TENANT_NAME;
    }

    private void setRequestObjectValues(String requestObjectString, RequestObject requestObjectInstance) throws RequestObjectException {
        if (isEmpty(requestObjectString)) {
            return;
        }
        try {
            JOSEObject jwt = JOSEObject.parse(requestObjectString);
            if (jwt.getHeader().getAlgorithm() == null || jwt.getHeader().getAlgorithm().equals(JWSAlgorithm.NONE)) {
                requestObjectInstance.setPlainJWT(PlainJWT.parse(requestObjectString));
            } else {
                requestObjectInstance.setSignedJWT(SignedJWT.parse(requestObjectString));
            }
        } catch (java.text.ParseException e) {
            String errorMessage = "No Valid Request Object is found in the request.";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, errorMessage);
        }
    }

}