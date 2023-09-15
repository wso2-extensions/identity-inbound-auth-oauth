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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.json.JSONObject;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.utils.DiagnosticLog;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

/**
 * OAuth 2 authorization request.
 */
public class CarbonOAuthAuthzRequest extends OAuthAuthzRequest {

    private static final Log log = LogFactory.getLog(CarbonOAuthTokenRequest.class);


    public CarbonOAuthAuthzRequest(HttpServletRequest request) throws OAuthSystemException,
            OAuthProblemException {

        super(request);
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
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                        .inputParam(OAuthConstants.LogConstants.InputKeys.RESPONSE_TYPE, responseTypeValue)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, getClientId())
                        .resultMessage("Invalid response_type parameter.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            throw OAuthUtils.handleOAuthProblemException("Invalid response_type parameter value");
        }

        return OAuthUtils.instantiateClass(clazz);
    }

    @Override
    public String getState() {

         /*If request object is present, get the state from the request object.
         This state value was required to overridden from the request object in order to make sure the correct state
         value(value inside the request object) is sent in error responses prior to building the request object.*/
        if (StringUtils.isNotBlank(getParam(Constants.REQUEST))) {
            byte[] requestObject;
            try {
                requestObject = Base64.getDecoder().decode(getParam(Constants.REQUEST).split("\\.")[1]);
            } catch (IllegalArgumentException e) {
                // Decode if the requestObject is base64-url encoded.
                requestObject = Base64.getUrlDecoder().decode(getParam(Constants.REQUEST).split("\\.")[1]);
            }
            JSONObject requestObjectJson = new JSONObject(new String(requestObject, StandardCharsets.UTF_8));
            return requestObjectJson.has(OAuth.OAUTH_STATE) ? requestObjectJson.getString(OAuth.OAUTH_STATE) : null;
        } else {
            return super.getState();
        }
    }
}
