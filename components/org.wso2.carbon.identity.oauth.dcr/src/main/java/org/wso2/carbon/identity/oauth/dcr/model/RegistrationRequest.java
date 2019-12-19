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

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * DCR Request data for Register an OAuth application.
 */
public class RegistrationRequest extends IdentityRequest {

    private static final long serialVersionUID = -6698974259780031092L;
    private RegistrationRequestProfile registrationRequestProfile = null;

    public RegistrationRequest(RegistrationRequestBuilder builder) throws FrameworkClientException {

        super(builder);
        this.registrationRequestProfile = builder.registrationRequestProfile;

    }

    public RegistrationRequestProfile getRegistrationRequestProfile() {

        return registrationRequestProfile;
    }

    /**
     * OAuth DCR request builder.
     */
    public static class RegistrationRequestBuilder extends IdentityRequestBuilder {

        private RegistrationRequestProfile registrationRequestProfile = null;

        public RegistrationRequestBuilder(HttpServletRequest request,
                                          HttpServletResponse response) {

            super(request, response);
        }

        public RegistrationRequestProfile getRegistrationRequestProfile() {

            return registrationRequestProfile;
        }

        public RegistrationRequestBuilder setRegistrationRequestProfile(
                RegistrationRequestProfile registrationRequestProfile) {

            this.registrationRequestProfile = registrationRequestProfile;
            return this;
        }

        @Override
        public RegistrationRequest build() throws FrameworkRuntimeException, FrameworkClientException {

            return new RegistrationRequest(this);
        }
    }

    /**
     * Contains the constants used in registration request.
     */
    public static class RegisterRequestConstant extends IdentityRequestConstants {

        public static final String REDIRECT_URIS = "redirect_uris";
        public static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
        public static final String GRANT_TYPES = "grant_types";
        public static final String RESPONSE_TYPES = "response_types";
        public static final String CLIENT_NAME = "client_name";
        public static final String CLIENT_URI = "client_uri";
        public static final String LOGO_URI = "logo_uri";
        public static final String SCOPE = "scope";
        public static final String CONTACTS = "contacts";
        public static final String TOS_URI = "tos_uri";
        public static final String POLICY_URI = "policy_uri";
        public static final String JWKS_URI = "jwks_uri";
        public static final String JWKS = "jwks";
        public static final String SOFTWARE_ID = "software_id";
        public static final String SOFTWARE_VERSION = "software_version";

        public static final String EXT_PARAM_OWNER = "ext_param_owner";

    }

}
