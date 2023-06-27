/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.par.core.ParAuthServiceImpl;
import org.wso2.carbon.identity.oauth.par.model.OAuthParRequestWrapper;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * OAuth 2 authorization request.
 */
public class CarbonOAuthAuthzRequest extends OAuthAuthzRequest {

    private static final Log log = LogFactory.getLog(CarbonOAuthTokenRequest.class);


    public CarbonOAuthAuthzRequest(HttpServletRequest request) throws OAuthSystemException,
            OAuthProblemException {

        super(buildRequest(request));
    }

    /*
        If request_uri parameter is present in the parameter map, consider request as a PAR request and
        use OAuthParRequestWrapper to make the request's parameter map contain the parameter map obtained from
        the PAR endpoint as parameters such as response_type are only provided in the PAR request,
        but are needed in the Authorization request for validations.
     */
    private static HttpServletRequest buildRequest(HttpServletRequest request) throws OAuthProblemException {

        // If request_uri is there consider as par request.
        if (request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI) != null) {
            return new OAuthParRequestWrapper(request, OAuth2ServiceComponentHolder.getParAuthService());
        }
        return request;
    }

    protected OAuthValidator<HttpServletRequest> initValidator() throws OAuthProblemException, OAuthSystemException {

        String responseTypeValue = getParam(OAuth.OAUTH_RESPONSE_TYPE);
        if (OAuthUtils.isEmpty(responseTypeValue)) {
            throw OAuthUtils.handleOAuthProblemException("Missing response_type parameter value");
        }

        Class<? extends OAuthValidator<HttpServletRequest>> clazz = OAuthServerConfiguration
                .getInstance().getSupportedResponseTypeValidators().get(responseTypeValue);

        if (clazz == null) {
            if (log.isDebugEnabled()) {
                //Do not change this log format as these logs use by external applications
                log.debug("Unsupported Response Type : " + responseTypeValue +
                        " for client id : " + getClientId());
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("response_type", responseTypeValue);
                params.put("client_id", getClientId());
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "Invalid response_type parameter.",
                        "validate-input-parameters", null);
            }
            throw OAuthUtils.handleOAuthProblemException("Invalid response_type parameter value");
        }

        return OAuthUtils.instantiateClass(clazz);
    }
}
