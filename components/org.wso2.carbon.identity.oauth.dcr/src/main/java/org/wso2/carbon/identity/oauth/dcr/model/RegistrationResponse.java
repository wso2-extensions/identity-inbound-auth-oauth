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

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;


public class RegistrationResponse extends IdentityResponse {


    private static final long serialVersionUID = -8410341453019535800L;
    private RegistrationResponseProfile registrationResponseProfile = null;

    protected RegistrationResponse(
            DCRRegisterResponseBuilder builder) {
        super(builder);
        this.registrationResponseProfile = builder.registrationResponseProfile;
    }

    public RegistrationResponseProfile getRegistrationResponseProfile() {
        return registrationResponseProfile;
    }

    public static class DCRRegisterResponseBuilder extends IdentityResponseBuilder {

        private RegistrationResponseProfile registrationResponseProfile = null;

        public DCRRegisterResponseBuilder(
                IdentityMessageContext context) {
            super(context);
        }

        public DCRRegisterResponseBuilder() {
        }

        public DCRRegisterResponseBuilder setRegistrationResponseProfile(
                RegistrationResponseProfile registrationResponseProfile) {
            this.registrationResponseProfile = registrationResponseProfile;
            return this;
        }

        @Override
        public RegistrationResponse build() {
            return new RegistrationResponse(this);
        }
    }

    public static class DCRegisterResponseConstants extends IdentityResponseConstants {
        public static final String CLIENT_ID = "client_id";
        public static final String CLIENT_SECRET = "client_secret";
        public static final String CLIENT_NAME = "client_name";
        public static final String CLIENT_ID_ISSUED_AT = "client_id_issued_at";
        public static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";
        public final static String REDIRECT_URIS = "redirect_uris";
        public final static String GRANT_TYPES = "grant_types";

    }
}
