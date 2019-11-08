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
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.wrappers.CibaAuthRequestWrapper;
import org.wso2.carbon.identity.oauth.ciba.wrappers.CibaAuthResponseWrapper;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;

import java.net.URISyntaxException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;

/**
 * Handles making authorize request to the authorize request.
 */
public class CibaAuthzHandler {

    private static final Log log = LogFactory.getLog(CibaAuthzHandler.class);

    OAuth2AuthzEndpoint authzEndPoint = new OAuth2AuthzEndpoint();

    private CibaAuthzHandler() {

    }

    private static CibaAuthzHandler CibaAuthzHandlerInstance = new CibaAuthzHandler();

    public static CibaAuthzHandler getInstance() {

        if (CibaAuthzHandlerInstance == null) {

            synchronized (CibaAuthzHandler.class) {

                if (CibaAuthzHandlerInstance == null) {

                    /* instance will be created at request time */
                    CibaAuthzHandlerInstance = new CibaAuthzHandler();
                }
            }
        }
        return CibaAuthzHandlerInstance;
    }

    /**
     * Trigger authorize request after building the url.
     *
     * @param authzRequestDto AuthorizeRequest Data Transfer Object..
     * @throws CibaAuthFailedException CibaAuthentication related exception.
     */
    public void initiateAuthzRequest(AuthzRequestDTO authzRequestDto, @Context HttpServletRequest request,
                                     @Context HttpServletResponse response)
            throws CibaAuthFailedException {

        // Add custom parameters to the request by wrapping.
        try {
            CibaAuthRequestWrapper cibaAuthRequestWrapper = new CibaAuthRequestWrapper(request);

            cibaAuthRequestWrapper.setParameter(CibaParams.SCOPE, authzRequestDto.getScope());
            cibaAuthRequestWrapper.setParameter(CibaParams.RESPONSE_TYPE, CibaParams.RESPONSE_TYPE_VALUE);
            cibaAuthRequestWrapper.setParameter(CibaParams.NONCE, authzRequestDto.getAuthReqIDasState());
            cibaAuthRequestWrapper.setParameter(CibaParams.REDIRECT_URI, authzRequestDto.getCallBackUrl());
            cibaAuthRequestWrapper.setParameter(CibaParams.CLIENT_ID, authzRequestDto.getClient_id());
            cibaAuthRequestWrapper.setParameter(CibaParams.USER_IDENTITY, authzRequestDto.getUser());
            if (!StringUtils.isBlank(authzRequestDto.getBindingMessage())) {
                cibaAuthRequestWrapper.setParameter(CibaParams.BINDING_MESSAGE, authzRequestDto.getBindingMessage());
            }

            if (!StringUtils.isBlank(authzRequestDto.getTransactionContext())) {
                cibaAuthRequestWrapper.setParameter(CibaParams.TRANSACTION_CONTEXT,
                        authzRequestDto.getTransactionContext());

            }
            // Create an instance of response.
            CibaAuthResponseWrapper commonAuthResponseWrapper = new CibaAuthResponseWrapper(response);

            if (log.isDebugEnabled()) {
                log.debug("Building AuthorizeRequest wrapper from CIBA component for the user : " +
                        authzRequestDto.getUser() + " to continue the authentication request made by client with " +
                        "clientID : " + authzRequestDto.getClient_id());
            }

            // Fire authorize request and forget.
            fireAuthzReq(cibaAuthRequestWrapper, commonAuthResponseWrapper);

        } catch (CibaAuthFailedException e) {
            throw new CibaAuthFailedException(e.getStatus(), e.getErrorCode(), e.getErrorDescription());
        }
    }

    /**
     * Initiate the  authorize request.
     *
     * @param requestWrapper  Authentication request wrapper.
     * @param responseWrapper AuthenticationResponse wrapper.
     */
    private void fireAuthzReq(CibaAuthRequestWrapper requestWrapper, CibaAuthResponseWrapper responseWrapper)
            throws CibaAuthFailedException {

        try {
            authzEndPoint.authorize(requestWrapper, responseWrapper);
        } catch (URISyntaxException | InvalidRequestParentException e) {
            throw new CibaAuthFailedException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    ErrorCodes.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}

