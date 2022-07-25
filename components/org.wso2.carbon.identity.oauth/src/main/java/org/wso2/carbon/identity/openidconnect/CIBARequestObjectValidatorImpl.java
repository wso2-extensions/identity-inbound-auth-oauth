/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.RequestObjectValidatorUtil;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

/**
 * This class validates request object parameter value which comes with the OIDC CIBA authorization request
 */

public class CIBARequestObjectValidatorImpl implements RequestObjectValidator {

    private static final Log log = LogFactory.getLog(CIBARequestObjectValidatorImpl.class);

    @Override
    public boolean isSigned(RequestObject requestObject) {

        return requestObject.getSignedJWT() != null;
    }

    @Override
    public boolean validateSignature(RequestObject requestObject, OAuth2Parameters oAuth2Parameters) throws
            RequestObjectException {

        return RequestObjectValidatorUtil.validateSignature(requestObject, oAuth2Parameters);
    }

    /**
     * Decide whether this request object is a signed object encrypted object or a nested object.
     *
     * @param requestObject    request object
     * @param oAuth2Parameters oAuth2Parameters
     * @throws RequestObjectException
     */
    @Override
    public boolean validateRequestObject(RequestObject requestObject, OAuth2Parameters oAuth2Parameters)
            throws RequestObjectException {

        if (OAuthServerConfiguration.getInstance().isFapiCiba()) {
            long expiryTime = requestObject.getClaimsSet().getExpirationTime().getTime();
            long nbfTime = requestObject.getClaimsSet().getNotBeforeTime().getTime();
            long requestValidityPeriod = expiryTime - nbfTime;
            if (requestValidityPeriod > 3600000) {
                throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "Request object invalid: Difference between validity period and nbf greater than 1 hour");
            }
        }
        return true;

    }

}
