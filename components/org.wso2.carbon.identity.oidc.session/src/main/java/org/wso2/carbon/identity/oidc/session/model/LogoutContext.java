/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session.model;

/**
 * This class holds context information required for logout.
 */
public class LogoutContext {

    private boolean isAPIBasedLogout;
    private boolean isAPIBasedLogoutWithoutCookies;
    private String clientId;
    private String sessionId;

    public boolean isAPIBasedLogout() {

        return isAPIBasedLogout;
    }

    public void setAPIBasedLogout(boolean isAPIBasedLogout) {

        this.isAPIBasedLogout = isAPIBasedLogout;
    }

    public boolean isAPIBasedLogoutWithoutCookies() {

        return isAPIBasedLogoutWithoutCookies;
    }

    public void setAPIBasedLogoutWithoutCookies(boolean isAPIBasedLogoutWithoutCookies) {

        this.isAPIBasedLogoutWithoutCookies = isAPIBasedLogoutWithoutCookies;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getSessionId() {

        return sessionId;
    }

    public void setSessionId(String sessionId) {

        this.sessionId = sessionId;
    }
}
