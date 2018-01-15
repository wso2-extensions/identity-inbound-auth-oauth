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

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * This class is used to build request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */
public class RequestParamRequestObjectBuilder implements RequestObjectBuilder {

    private static Log log = LogFactory.getLog(RequestParamRequestObjectBuilder.class);

    /**
     * Builds request object which comes as the value of the request query parameter of OIDC authorization request
     *
     * @param requestObjectParamValue request object
     * @throws RequestObjectException
     */
    @Override
    public void buildRequestObject(String requestObjectParamValue, OAuth2Parameters oAuth2Parameters,
                                   RequestObject requestObjectInstance) throws RequestObjectException {

        RequestObjectValidator requestObjectValidator = OAuthServerConfiguration.getInstance()
                .getRequestObjectValidator();
        if (requestObjectValidator.isEncrypted(requestObjectParamValue)) {
            requestObjectParamValue = requestObjectValidator.decrypt(requestObjectParamValue, oAuth2Parameters);
        }
        setRequestObjectValues(requestObjectParamValue, requestObjectInstance);
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
            log.error(errorMessage);
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, errorMessage);
        }
    }

}
