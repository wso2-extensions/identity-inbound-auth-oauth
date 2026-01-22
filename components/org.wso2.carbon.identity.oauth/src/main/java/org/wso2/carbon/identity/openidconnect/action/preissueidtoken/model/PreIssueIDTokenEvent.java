/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model;

import org.wso2.carbon.identity.action.execution.api.model.Event;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Request;
import org.wso2.carbon.identity.action.execution.api.model.Tenant;
import org.wso2.carbon.identity.action.execution.api.model.User;
import org.wso2.carbon.identity.action.execution.api.model.UserStore;

/**
 * This class models the event at a pre issue id token trigger.
 * PreIssueIdTokenEvent is the entity that represents the event that is sent to the Action
 * over {@link org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest}.
 */
public class PreIssueIDTokenEvent extends Event {

    private final IDToken idToken;

    public PreIssueIDTokenEvent(Builder builder) {

        this.idToken = builder.idToken;
        this.request = builder.request;
        this.organization = builder.organization;
        this.tenant = builder.tenant;
        this.user = builder.user;
        this.userStore = builder.userStore;
    }

    public IDToken getIdToken() {

        return idToken;
    }

    /**
     * Builder for the PreIssueIdTokenEvent.
     */
    public static class Builder {

        private IDToken idToken;
        private Request request;
        private Organization organization;
        private Tenant tenant;
        private User user;
        private UserStore userStore;

        public Builder idToken(IDToken idToken) {

            this.idToken = idToken;
            return this;
        }

        public Builder request(Request request) {

            this.request = request;
            return this;
        }

        public Builder organization(Organization organization) {

            this.organization = organization;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder userStore(UserStore userStore) {

            this.userStore = userStore;
            return this;
        }

        public PreIssueIDTokenEvent build() {

            return new PreIssueIDTokenEvent(this);
        }
    }
}
