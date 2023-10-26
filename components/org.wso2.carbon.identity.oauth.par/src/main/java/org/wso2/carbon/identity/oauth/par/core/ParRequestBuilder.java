/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.par.core;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.exceptions.ParAuthFailureException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.internal.ParAuthServiceComponentDataHolder;
import org.wso2.carbon.identity.oauth2.OAuthAuthorizationRequestBuilder;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.InputKeys.REQUEST_BUILDER;

/**
 * This builds the authorization request if the incoming request satisfies the PAR conditions.
 */
public class ParRequestBuilder implements OAuthAuthorizationRequestBuilder {

    private static final String REQUEST_BUILDER_NAME = "pushedAuthorizationRequestBuilder";

    @Override
    public HttpServletRequest buildRequest(HttpServletRequest request) throws IdentityException {

        String requestUri = request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI);
        String uuid = requestUri.replaceFirst(ParConstants.REQUEST_URI_PREFIX, "");
        Map<String, String> params;

        try {
            params = ParAuthServiceComponentDataHolder.getInstance().getParAuthService()
                    .retrieveParams(uuid, request.getParameter(OAuthConstants.OAuth20Params.CLIENT_ID));
        } catch (ParClientException e) {
            throw new ParAuthFailureException(e.getErrorCode(), e.getMessage(), e);
        } catch (ParCoreException e) {
            throw new ParAuthFailureException(OAuth2ErrorCodes.SERVER_ERROR,
                    "Error occurred while retrieving params from PAR request", e);
        }
        request.setAttribute(OAuthConstants.IS_PUSH_AUTHORIZATION_REQUEST, true);
        return new OAuthParRequestWrapper(request, params);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        boolean canHandle = (request != null) &&
                StringUtils.startsWith(request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI),
                        ParConstants.REQUEST_URI_PREFIX);

        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HANDLE_REQUEST);
            diagnosticLogBuilder
                    .inputParam(LogConstants.InputKeys.CLIENT_ID,
                            request.getParameter(OAuthConstants.OAuth20Params.CLIENT_ID))
                    .inputParam(REQUEST_BUILDER, getName())
                    .resultMessage("PAR request builder handling the request")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    public String getName() {

        return REQUEST_BUILDER_NAME;
    }
}
