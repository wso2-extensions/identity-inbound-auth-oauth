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

package org.wso2.carbon.identity.oauth.dcr.model;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * DCR Request data for Register a oauth application
 */
public class RegistrationRequest extends IdentityRequest {

    private RegistrationRequestProfile registrationRequestProfile = null;

    public RegistrationRequest(RegistrationRequestBuilder builder) {

        super(builder);
        this.registrationRequestProfile = builder.registrationRequestProfile;
    }

    public RegistrationRequestProfile getRegistrationRequestProfile() {
        return registrationRequestProfile;
    }

    public static class RegistrationRequestBuilder extends IdentityRequestBuilder {

        private RegistrationRequestProfile registrationRequestProfile = null;

        public RegistrationRequestBuilder(HttpServletRequest request,
                                          HttpServletResponse response) {
            super(request, response);
        }

        @Override
        public RegistrationRequest build() throws FrameworkRuntimeException {
            return new RegistrationRequest(this);
        }

        public RegistrationRequestProfile getRegistrationRequestProfile() {
            return registrationRequestProfile;
        }

        public RegistrationRequestBuilder setRegistrationRequestProfile(
                RegistrationRequestProfile registrationRequestProfile) {
            this.registrationRequestProfile = registrationRequestProfile;
            return this;
        }
    }

    public static class RegisterRequestConstant extends IdentityRequestConstants {

        public final static String REDIRECT_URIS = "redirect_uris";
        public final static String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
        public final static String GRANT_TYPES = "grant_types";
        public final static String RESPONSE_TYPES = "response_types";
        public final static String CLIENT_NAME = "client_name";
        public final static String CLIENT_URI = "client_uri";
        public final static String LOGO_URI = "logo_uri";
        public final static String SCOPE = "scope";
        public final static String CONTACTS = "contacts";
        public final static String TOS_URI = "tos_uri";
        public final static String POLICY_URI = "policy_uri";
        public final static String JWKS_URI = "jwks_uri";
        public final static String JWKS = "jwks";
        public final static String SOFTWARE_ID = "software_id";
        public final static String SOFTWARE_VERSION = "software_version";

        public final static String EXT_PARAM_OWNER = "ext_param_owner";
    }
}
