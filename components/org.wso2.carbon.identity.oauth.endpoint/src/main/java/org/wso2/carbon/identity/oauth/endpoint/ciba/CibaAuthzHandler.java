/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;
import org.wso2.carbon.identity.oauth.ciba.wrappers.CibaAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.ciba.wrappers.CibaAuthResponseWrapper;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.Constants;

import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;

/**
 * Handles making authorize request to authorize endpoint as internal call.
 */
public class CibaAuthzHandler {

    private static final Log log = LogFactory.getLog(CibaAuthzHandler.class);

    OAuth2AuthzEndpoint authzEndPoint = new OAuth2AuthzEndpoint();

    /**
     * Trigger authorize request after building the url.
     *
     * @param authCodeResponse AuthorizeRequest Data Transfer Object..
     * @throws CibaAuthFailureException CibaAuthentication related exception.
     */
    public void initiateAuthzRequest(CibaAuthCodeResponse authCodeResponse, @Context HttpServletRequest request,
                                     @Context HttpServletResponse response) throws CibaAuthFailureException {

        // Add custom parameters to the request by wrapping.
        CibaAuthRequestWrapper cibaAuthRequestWrapper = new CibaAuthRequestWrapper(request);

        cibaAuthRequestWrapper.setParameter(Constants.SCOPE, OAuth2Util.buildScopeString(authCodeResponse.getScopes()));
        cibaAuthRequestWrapper.setParameter(Constants.RESPONSE_TYPE, CibaConstants.RESPONSE_TYPE_VALUE);
        cibaAuthRequestWrapper.setParameter(Constants.NONCE, authCodeResponse.getAuthReqId());
        cibaAuthRequestWrapper.setParameter(Constants.REDIRECT_URI, authCodeResponse.getCallBackUrl());
        cibaAuthRequestWrapper.setParameter(Constants.CLIENT_ID, authCodeResponse.getClientId());
        cibaAuthRequestWrapper.setParameter(CibaConstants.USER_IDENTITY, authCodeResponse.getUserHint());
        if (!StringUtils.isBlank(authCodeResponse.getBindingMessage())) {
            cibaAuthRequestWrapper.setParameter(CibaConstants.BINDING_MESSAGE, authCodeResponse.getBindingMessage());
        }

        if (!StringUtils.isBlank(authCodeResponse.getTransactionContext())) {
            cibaAuthRequestWrapper.setParameter(CibaConstants.TRANSACTION_CONTEXT,
                    authCodeResponse.getTransactionContext());
        }
        // Create an instance of response.
        CibaAuthResponseWrapper commonAuthResponseWrapper = new CibaAuthResponseWrapper(response);
        if (log.isDebugEnabled()) {
            log.debug("Building AuthorizeRequest wrapper from CIBA component for the user : " +
                    authCodeResponse.getUserHint() + " to continue the authentication request made by client with " +
                    "clientID : " + authCodeResponse.getClientId());
        }
        // Fire authorize request and forget.
        fireAuthzReq(cibaAuthRequestWrapper, commonAuthResponseWrapper);
    }

    /**
     * Initiate the  authorize request.
     *
     * @param requestWrapper  Authentication request wrapper.
     * @param responseWrapper AuthenticationResponse wrapper.
     */
    public void fireAuthzReq(CibaAuthRequestWrapper requestWrapper, CibaAuthResponseWrapper responseWrapper)
            throws CibaAuthFailureException {

        try {
            authzEndPoint.authorize(requestWrapper, responseWrapper);
        } catch (URISyntaxException | InvalidRequestParentException e) {
            throw new CibaAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error in making internal authorization call.", e);
        }
    }
}
