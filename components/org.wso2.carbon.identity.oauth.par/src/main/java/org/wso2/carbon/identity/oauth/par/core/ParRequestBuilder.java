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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.AbstractRequestBuilder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.DiagnosticLog;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.InputKeys.REQUEST_BUILDER;

/**
 * This builds the PAR request if the incoming request satisfies the PAR conditions.
 */
public class ParRequestBuilder implements AbstractRequestBuilder {

    private static final Log log = LogFactory.getLog(ParRequestBuilder.class);

    private static final String REQUEST_BUILDER_NAME = "Pushed authorization request builder";

    @Override
    public HttpServletRequest buildRequest(HttpServletRequest request) throws IdentityException {

        return new OAuthParRequestWrapper(request);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        // Requests that separately contain the scope `openid` will not be handled in the PAR flow since they are
        // considered as OIDC requests passed by reference. Refer section 6.2.2 of the OIDC Core spec.
        boolean isParRequest = !OAuth2Util.isOIDCAuthzRequest(OAuthUtils.decodeScopes(request.getParameter("scope")));
        boolean canHandle = StringUtils.isNotBlank(request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI))
                && isParRequest;

        if (!isParRequest) {
            log.debug("Request is an OIDC request. Therefore, PAR request builder cannot handle the request.");
        }

        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HANDLE_REQUEST);
            diagnosticLogBuilder
                    .inputParam(LogConstants.InputKeys.CLIENT_ID,
                            request.getParameter(OAuthConstants.OAuth20Params.CLIENT_ID))
                    .inputParam(REQUEST_BUILDER, getName())
                    .resultMessage("PAR request builder handling the request")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    public String getName() {

        return REQUEST_BUILDER_NAME;
    }
}
