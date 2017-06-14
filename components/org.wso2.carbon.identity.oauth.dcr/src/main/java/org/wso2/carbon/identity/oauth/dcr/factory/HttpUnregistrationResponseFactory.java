/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.factory;

import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.UnRegistrationException;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationResponse;

import javax.servlet.http.HttpServletResponse;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;

/**
 * Http UnRegistration Response Factory.
 */
public class HttpUnregistrationResponseFactory extends HttpIdentityResponseFactory {

    public static String BACKEND_FAILED = "backend_failed";

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if (identityResponse instanceof UnregistrationResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {
        HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(httpIdentityResponseBuilder, identityResponse);
        return httpIdentityResponseBuilder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder,
                       IdentityResponse identityResponse) {
        httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_NO_CONTENT);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                                              OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder =
                new HttpIdentityResponse.HttpIdentityResponseBuilder();
        String errorMessage = null;
        if (ErrorCodes.BAD_REQUEST.name().equals(exception.getErrorCode())) {
          errorMessage = generateErrorResponse(BACKEND_FAILED, exception.getMessage()).toJSONString();
        }
          builder.setBody(errorMessage);
          builder.setStatusCode(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
          builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                            OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
          builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                            OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
          return builder;
    }

    public boolean canHandle(FrameworkException exception) {
        if (exception instanceof UnRegistrationException) {
            return true;
        }
        return false;
    }

    protected JSONObject generateErrorResponse(String error, String description) {
        JSONObject obj = new JSONObject();
        obj.put("error", error);
        obj.put("error_description", description);
        return obj;
    }
}
