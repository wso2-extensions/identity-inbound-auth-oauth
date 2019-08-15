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
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;

import javax.servlet.http.HttpServletRequest;

public class CarbonOAuthAuthzRequest extends OAuthAuthzRequest {

    private static final Log log = LogFactory.getLog(CarbonOAuthTokenRequest.class);

    public CarbonOAuthAuthzRequest(HttpServletRequest request) throws OAuthSystemException, OAuthProblemException {
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
            throw OAuthUtils.handleOAuthProblemException("Invalid response_type parameter value");
        }

        return OAuthUtils.instantiateClass(clazz);
    }
}