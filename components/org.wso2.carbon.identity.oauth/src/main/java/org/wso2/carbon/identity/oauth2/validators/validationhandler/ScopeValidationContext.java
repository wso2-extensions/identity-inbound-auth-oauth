/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.validators.validationhandler;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.List;
import java.util.Map;

/**
 * Scope Validation Context is where we pass scope validation context to the scope validation handlers.
 */
public class ScopeValidationContext {

    private AuthenticatedUser authenticatedUser;
    private String appId;
    private String appTenantDomain;
    private String grantType;
    private String userType;

    private String policyId;
    private Map<String, List<String>> validatedScopesByHandler;

    /**
     * Get the authenticated user.
     *
     * @return AuthenticatedUser.
     */

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    /**
     * Set the authenticated user.
     *
     * @param authenticatedUser AuthenticatedUser.
     */
    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    /**
     * Get the application id.
     *
     * @return Application ID.
     */
    public String getAppId() {

        return appId;
    }

    /**
     * Set the application id.
     *
     * @param appId Application ID.
     */
    public void setAppId(String appId) {

        this.appId = appId;
    }

    /**
     * Get the validated scopes by handler
     *
     * @return Map of validated scopes.
     */
    public Map<String, List<String>> getValidatedScopesByHandler() {

        return validatedScopesByHandler;
    }

    /**
     * Set the validated scopes by handler.
     *
     * @param validatedScopesByHandler Map of validated scopes.
     */
    public void setValidatedScopesByHandler(Map<String, List<String>> validatedScopesByHandler) {

        this.validatedScopesByHandler = validatedScopesByHandler;
    }

    /**
     * Get the grant type.
     *
     * @return Grant type.
     */
    public String getGrantType() {

        return grantType;
    }

    /**
     * Set the grant type.
     *
     * @param grantType Grant type.
     */
    public void setGrantType(String grantType) {

        this.grantType = grantType;
    }

    /**
     * Get the policy id.
     *
     * @return Policy ID.
     */
    public String getPolicyId() {

        return policyId;
    }

    /**
     * Set the policy id.
     *
     * @param policyId Policy ID.
     */
    public void setPolicyId(String policyId) {

        this.policyId = policyId;
    }

    /**
     * Set the user type.
     *
     * @param userType User type.
     */
    public void setUserType(String userType) {

        this.userType = userType;
    }

    /**
     * Get the user type.
     *
     * @return User type.
     */
    public String getUserType() {

        return userType;
    }

    public String getAppTenantDomain() {

        return appTenantDomain;
    }

    public void setAppTenantDomain(String appTenantDomain) {

        this.appTenantDomain = appTenantDomain;
    }
}
