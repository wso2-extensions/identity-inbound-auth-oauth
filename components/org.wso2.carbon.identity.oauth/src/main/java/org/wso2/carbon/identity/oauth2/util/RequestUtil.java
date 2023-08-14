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
package org.wso2.carbon.identity.oauth2.util;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.OAuthAuthorizationRequestBuilder;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.InputKeys.REQUEST_BUILDER;

/**
 * This is a util class for building the request.
 */
public class RequestUtil {

    private RequestUtil() {

    }

    /**
     * This method builds the request according to the type which can handle it.
     *
     * @param request Incoming HttpServletRequest.
     * @return Built HttpServletRequest instance.
     * @throws IdentityException IdentityException.
     */
    public static HttpServletRequest buildRequest(HttpServletRequest request) throws IdentityException {

        List<OAuthAuthorizationRequestBuilder> oAuthAuthorizationRequestBuilders =
                OAuth2ServiceComponentHolder.getInstance().getAuthorizationRequestBuilders();

        for (OAuthAuthorizationRequestBuilder requestBuilder : oAuthAuthorizationRequestBuilders) {
            if (requestBuilder.canHandle(request)) {

                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.BUILD_REQUEST);
                    diagnosticLogBuilder
                            .inputParam(REQUEST_BUILDER, requestBuilder.getName())
                            .resultMessage("OAuth authorization request builder found for the request.")
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }

                return requestBuilder.buildRequest(request);
            }
        }

        return request;
    }
}
