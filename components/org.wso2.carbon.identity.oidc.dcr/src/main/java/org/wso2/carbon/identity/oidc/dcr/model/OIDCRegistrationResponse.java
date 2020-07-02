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

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;

/**
 * OIDC DCR Response data returned for registration request.
 */
@Deprecated
public class OIDCRegistrationResponse extends RegistrationResponse {

    private static final long serialVersionUID = 4698835928698402469L;

    protected OIDCRegistrationResponse(OIDCRegisterResponseBuilder builder) {

        super(builder);

    }

    /**
     * OIDC Registration response builder.
     */
    public static class OIDCRegisterResponseBuilder extends RegistrationResponse.DCRRegisterResponseBuilder {

        public OIDCRegisterResponseBuilder() {

            super();
        }

        public OIDCRegisterResponseBuilder(IdentityMessageContext context) {

            super(context);
        }

        @Override
        public OIDCRegistrationResponse build() {

            return new OIDCRegistrationResponse(this);
        }
    }

    /**
     * Contains the constants used in OIDC Register response.
     */
    public static class OIDCRegisterResponseConstants extends DCRegisterResponseConstants {

    }
}
