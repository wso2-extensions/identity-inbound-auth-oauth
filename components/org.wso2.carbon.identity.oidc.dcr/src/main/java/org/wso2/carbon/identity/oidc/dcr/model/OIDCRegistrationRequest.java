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

package org.wso2.carbon.identity.oidc.dcr.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * DCR Request data for Register a oauth application
 */
public class OIDCRegistrationRequest extends RegistrationRequest {

    public OIDCRegistrationRequest(OIDCRegistrationRequestBuilder builder) throws FrameworkClientException {
        super(builder);
    }


    public static class OIDCRegistrationRequestBuilder extends RegistrationRequestBuilder {
        public OIDCRegistrationRequestBuilder(HttpServletRequest request,
                                              HttpServletResponse response) {
            super(request, response);
        }

        @Override
        public RegistrationRequest build() throws FrameworkRuntimeException, FrameworkClientException {
            return new OIDCRegistrationRequest(this);
        }
    }

    public static class OIDCRegistrationRequestConstants extends RegisterRequestConstant {

        public final static String SECTOR_IDENTIFIER_URI = "sector_identifier_uri";
        public final static String SUBJECT_TYPE = "subject_type";
        public final static String ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg";
        public final static String ID_TOKEN_ENCRYPTED_RESPONSE_ALG = "id_token_encrypted_response_alg";
        public final static String ID_TOKEN_ENCRYPTED_RESPONSE_ENC = "id_token_encrypted_response_enc";
        public final static String USERINFO_SIGNED_RESPONSE_ALG = "userinfo_signed_response_alg";
        public final static String USERINFO_ENCRYPTED_RESPONSE_ALG = "userinfo_encrypted_response_alg";
        public final static String USERINFO_ENCRYPTED_RESPONSE_ENC = "userinfo_encrypted_response_enc";
        public final static String REQUEST_OBJECT_SIGNING_ALG = "request_object_signing_alg";
        public final static String REQUEST_OBJECT_ENCRYPTION_ALG = "request_object_encryption_alg";
        public final static String REQUEST_OBJECT_ENCRYPTION_ENC = "request_object_encryption_enc";
        public final static String TOKEN_ENDPOINT_AUTH_SIGNING_ALG = "token_endpoint_auth_signing_alg";
        public final static String DEFAULT_MAX_AGE = "default_max_age";
        public final static String REQUIRE_AUTH_TIME = "require_auth_time";
        public final static String DEFAULT_ACR_VALUES = "default_acr_values";
        public final static String INITIATE_LOGIN_URI = "initiate_login_uri";
        public final static String REQUEST_URIS = "request_uris";


    }
}
