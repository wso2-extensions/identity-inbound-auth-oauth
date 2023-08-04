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
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.model.OAuthParRequestWrapper;
import org.wso2.carbon.identity.oauth2.AbstractRequestBuilder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;

/**
 * This builds the PAR request if the incoming request satisfies the PAR conditions.
 */
public class ParRequestBuilder implements AbstractRequestBuilder {

    private static final String REQUEST_BUILDER_NAME = "Pushed authorization request builder";

    @Override
    public HttpServletRequest buildRequest(HttpServletRequest request) throws OAuthProblemException {

        return new OAuthParRequestWrapper(request);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        boolean isOIDCRequest = OAuth2Util.isOIDCAuthzRequest(OAuthUtils.decodeScopes(request.getParameter("scope")));
        return StringUtils.isNotBlank(request.getParameter(OAuthConstants.OAuth20Params.REQUEST_URI)) && !isOIDCRequest;
    }

    @Override
    public String getName() {

        return REQUEST_BUILDER_NAME;
    }

}
