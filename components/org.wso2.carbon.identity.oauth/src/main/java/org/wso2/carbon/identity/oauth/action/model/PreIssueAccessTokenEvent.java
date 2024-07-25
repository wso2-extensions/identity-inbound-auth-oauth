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

package org.wso2.carbon.identity.oauth.action.model;

import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.Organization;
import org.wso2.carbon.identity.action.execution.model.Request;
import org.wso2.carbon.identity.action.execution.model.Tenant;
import org.wso2.carbon.identity.action.execution.model.User;
import org.wso2.carbon.identity.action.execution.model.UserStore;

/**
 * This class models the event at a pre issue access token trigger.
 * PreIssueAccessTokenEvent is the entity that represents the event that is sent to the Action
 * over {@link org.wso2.carbon.identity.action.execution.model.ActionExecutionRequest}.
 */
public class PreIssueAccessTokenEvent extends Event {

    private final AccessToken accessToken;

    private PreIssueAccessTokenEvent(Builder builder) {

        this.accessToken = builder.accessToken;
        this.request = builder.request;
        this.organization = builder.organization;
        this.tenant = builder.tenant;
        this.user = builder.user;
        this.userStore = builder.userStore;
    }

    public AccessToken getAccessToken() {

        return accessToken;
    }

    /**
     * Builder for the PreIssueAccessTokenEvent.
     */
    public static class Builder {

        private AccessToken accessToken;
        private Request request;
        private Organization organization;
        private Tenant tenant;
        private User user;

        private UserStore userStore;

        public Builder accessToken(AccessToken accessToken) {

            this.accessToken = accessToken;
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

        public PreIssueAccessTokenEvent build() {

            return new PreIssueAccessTokenEvent(this);
        }
    }
}
