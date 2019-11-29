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
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.wrappers.CibaAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.ciba.wrappers.CibaAuthResponseWrapper;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
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

    private CibaAuthzHandler() {

    }

    private static CibaAuthzHandler cibaAuthzHandler = new CibaAuthzHandler();

    public static CibaAuthzHandler getInstance() {

        return cibaAuthzHandler;
    }

    /**
     * Trigger authorize request after building the url.
     *
     * @param authResponseDTO AuthorizeRequest Data Transfer Object..
     * @throws CibaClientException CibaAuthentication related exception.
     */
    public void initiateAuthzRequest(CibaAuthResponseDTO authResponseDTO, @Context HttpServletRequest request,
                                     @Context HttpServletResponse response) throws CibaClientException {

        // Add custom parameters to the request by wrapping.
        CibaAuthRequestWrapper cibaAuthRequestWrapper = new CibaAuthRequestWrapper(request);

        cibaAuthRequestWrapper.setParameter(Constants.SCOPE, authResponseDTO.getScopes());
        cibaAuthRequestWrapper.setParameter(Constants.RESPONSE_TYPE, CibaConstants.RESPONSE_TYPE_VALUE);
        cibaAuthRequestWrapper.setParameter(Constants.NONCE, authResponseDTO.getAuthReqId());
        cibaAuthRequestWrapper.setParameter(Constants.REDIRECT_URI, authResponseDTO.getCallBackUrl());
        cibaAuthRequestWrapper.setParameter(Constants.CLIENT_ID, authResponseDTO.getClientId());
        cibaAuthRequestWrapper.setParameter(CibaConstants.USER_IDENTITY, authResponseDTO.getUserHint());
        if (!StringUtils.isBlank(authResponseDTO.getBindingMessage())) {
            cibaAuthRequestWrapper.setParameter(CibaConstants.BINDING_MESSAGE, authResponseDTO.getBindingMessage());
        }

        if (!StringUtils.isBlank(authResponseDTO.getTransactionContext())) {
            cibaAuthRequestWrapper.setParameter(CibaConstants.TRANSACTION_CONTEXT,
                    authResponseDTO.getTransactionContext());
        }
        // Create an instance of response.
        CibaAuthResponseWrapper commonAuthResponseWrapper = new CibaAuthResponseWrapper(response);
        if (log.isDebugEnabled()) {
            log.debug("Building AuthorizeRequest wrapper from CIBA component for the user : " +
                    authResponseDTO.getUserHint() + " to continue the authentication request made by client with " +
                    "clientID : " + authResponseDTO.getClientId());
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
    private void fireAuthzReq(CibaAuthRequestWrapper requestWrapper, CibaAuthResponseWrapper responseWrapper)
            throws CibaClientException {

        try {
            authzEndPoint.authorize(requestWrapper, responseWrapper);
        } catch (URISyntaxException | InvalidRequestParentException e) {
            throw new CibaClientException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    OAuth2ErrorCodes.SERVER_ERROR, "error in making internal authorization call.", e);
        }
    }
}
