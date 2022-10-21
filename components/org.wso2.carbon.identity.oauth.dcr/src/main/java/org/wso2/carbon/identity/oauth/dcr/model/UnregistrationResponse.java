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

/**
 * DCR Response data returned after un registering an OAuth application.
 */
public class UnregistrationResponse extends IdentityResponse {

    private static final long serialVersionUID = -4059676691166142155L;
    private boolean isUnregistered = false;

    protected UnregistrationResponse(
            DCUnregisterResponseBuilder builder) {

        super(builder);
        this.isUnregistered = builder.isUnregistered;
    }

    public boolean isUnregistered() {

        return isUnregistered;
    }

    /**
     * OAuth DCR un registration response builder.
     */
    public static class DCUnregisterResponseBuilder extends IdentityResponseBuilder {

        private boolean isUnregistered = false;

        public DCUnregisterResponseBuilder() {

            super();
        }

        public DCUnregisterResponseBuilder(
                IdentityMessageContext context) {

            super(context);
        }

        public DCUnregisterResponseBuilder setIsUnregistered(boolean isUnregistered) {

            this.isUnregistered = isUnregistered;
            return this;
        }

        @Override
        public UnregistrationResponse build() {

            return new UnregistrationResponse(this);
        }
    }
}
