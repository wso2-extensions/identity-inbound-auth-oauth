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
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;


public class UnregistrationRequest extends IdentityRequest {

    private String consumerKey;
    private String applicationName;
    private String userId;

    protected UnregistrationRequest(DCRUnregisterRequestBuilder builder) throws FrameworkClientException {
        super(builder);
        this.consumerKey = builder.consumerKey;
        this.applicationName = builder.applicationName;
        this.userId = builder.userId;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public String getUserId() {
        return userId;
    }

    public static class DCRUnregisterRequestBuilder extends IdentityRequestBuilder {
        private String consumerKey;
        private String applicationName;
        private String userId;

        public void setConsumerKey(String consumerKey) {
            this.consumerKey = consumerKey;
        }

        public void setApplicationName(String applicationName) {
            this.applicationName = applicationName;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public UnregistrationRequest build() throws FrameworkClientException {
            return new UnregistrationRequest(this);
        }
    }
}
