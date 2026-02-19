/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;

import java.util.Map;

/**
 * Interface for resolving user identity from CIBA login_hint.
 */
public interface CibaUserResolver {

    /**
     * Resolve user from login_hint and return user with claims.
     *
     * @param loginHint    The login hint (username or email)
     * @param tenantDomain The tenant domain
     * @return ResolvedUser containing user details and claims
     * @throws CibaCoreException If user resolution fails
     */
    ResolvedUser resolveUser(String loginHint, String tenantDomain) throws CibaClientException, CibaCoreException;

    /**
     * Represents a resolved user with claims.
     */
    class ResolvedUser {

        private String userId;
        private String username;
        private String userStoreDomain;
        private String tenantDomain;
        private String email;
        private String mobile;
        private Map<String, String> claims;

        public void setUserId(String userId) {

            this.userId = userId;
        }

        public String getUserId() {
            return userId;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getUserStoreDomain() {
            return userStoreDomain;
        }

        public void setUserStoreDomain(String userStoreDomain) {
            this.userStoreDomain = userStoreDomain;
        }

        public String getTenantDomain() {
            return tenantDomain;
        }

        public void setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getMobile() {
            return mobile;
        }

        public void setMobile(String mobile) {
            this.mobile = mobile;
        }

        public Map<String, String> getClaims() {
            return claims;
        }

        public void setClaims(Map<String, String> claims) {
            this.claims = claims;
        }
    }
}
