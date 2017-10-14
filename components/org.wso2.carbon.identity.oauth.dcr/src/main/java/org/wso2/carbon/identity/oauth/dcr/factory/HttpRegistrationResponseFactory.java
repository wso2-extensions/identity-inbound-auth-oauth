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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.ReadException;
import org.wso2.carbon.identity.oauth.dcr.exception.RegistrationException;
import org.wso2.carbon.identity.oauth.dcr.exception.UpdateException;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.util.ErrorCodes;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Http Registration Response Factory.
 */
public class HttpRegistrationResponseFactory extends HttpIdentityResponseFactory {

    public static String INVALID_REDIRECT_URI = "invalid_redirect_uri";
    public static String INVALID_CLIENT_METADATA = "invalid_client_metadata";
    public static String INVALID_SOFTWARE_STATEMENT = "invalid_software_statement";
    public static String UNAPPROVED_SOFTWARE_STATEMENT = "unapproved_software_statement";
    public static String BACKEND_FAILED = "backend_failed";
    private static Log log = LogFactory.getLog(HttpRegistrationResponseFactory.class);

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
        RegistrationResponse registrationResponse=null;
        if (identityResponse instanceof RegistrationResponse) {
            registrationResponse = (RegistrationResponse) identityResponse;
            httpIdentityResponseBuilder.setBody(generateSuccessfulResponse(registrationResponse).toJSONString());
            httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
            httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                    OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
            httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                    OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
            httpIdentityResponseBuilder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        } else {
            // This else part will not be reached from application logic.
            log.error("Can't create httpIdentityResponseBuilder. identityResponse is not an instance of " +
                    "RegistrationResponse");
        }
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {
        HttpIdentityResponse.HttpIdentityResponseBuilder builder =
                new HttpIdentityResponse.HttpIdentityResponseBuilder();
        String errorMessage = "";
        if (ErrorCodes.META_DATA_VALIDATION_FAILED.name().equals(exception.getErrorCode())) {
            errorMessage = generateErrorResponse(INVALID_CLIENT_METADATA, exception.getMessage()).toJSONString();
        } else if (ErrorCodes.BAD_REQUEST.name().equals(exception.getErrorCode())) {
            errorMessage = generateErrorResponse(BACKEND_FAILED, exception.getMessage()).toJSONString();
        }
        builder.setBody(errorMessage);
        builder.setStatusCode(HttpServletResponse.SC_BAD_REQUEST);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                          OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                          OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
        builder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        return builder;
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {

        return identityResponse instanceof RegistrationResponse;
    }

    public boolean canHandle(FrameworkException exception) {

        if (exception instanceof RegistrationException) {
            return true;
        } else if (exception instanceof ReadException) {
            return true;
        } else if (exception instanceof UpdateException) {
            return true;
        }
        return false;
    }


    protected JSONObject generateSuccessfulResponse(RegistrationResponse registrationResponse) {
        JSONObject obj = new JSONObject();
        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_ID, registrationResponse
                .getRegistrationResponseProfile().getClientId());
        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_NAME, registrationResponse
                .getRegistrationResponseProfile()
                .getClientName());
        JSONArray jsonArray = new JSONArray();
        for (String redirectUri : registrationResponse.getRegistrationResponseProfile().getRedirectUrls()) {
            jsonArray.add(redirectUri);
        }
        obj.put(RegistrationResponse.DCRegisterResponseConstants.REDIRECT_URIS, jsonArray);

        jsonArray = new JSONArray();
        for (String grantType : registrationResponse.getRegistrationResponseProfile().getGrantTypes()) {
            jsonArray.add(grantType);
        }
        obj.put(RegistrationResponse.DCRegisterResponseConstants.GRANT_TYPES, jsonArray);

        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_SECRET, registrationResponse
                .getRegistrationResponseProfile()
                .getClientSecret());
        obj.put(RegistrationResponse.DCRegisterResponseConstants.CLIENT_SECRET_EXPIRES_AT, registrationResponse
                .getRegistrationResponseProfile()
                .getClientSecretExpiresAt());
        return obj;
    }

    protected JSONObject generateErrorResponse(String error, String description) {
        JSONObject obj = new JSONObject();
        obj.put("error", error);
        obj.put("error_description", description);
        return obj;
    }


}
