/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeConsentException;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;

import java.util.List;

/**
 * This interface defines the API for user consent management for OAuth scopes.
 */
public interface OAuthUserConsentedScopesDAO {

    /**
     * Retrieve the user consent given for OAuth scopes for a given application.
     *
     * @param userId    User identifier.
     * @param appId     Application identifier.
     * @param tenantId  Tenant Id.
     * @return  {@link UserApplicationScopeConsentDO}
     * @throws IdentityOAuth2ScopeConsentException
     */
    UserApplicationScopeConsentDO getUserConsentForApplication(String userId, String appId, int tenantId)
            throws IdentityOAuth2ScopeConsentException;

    /**
     * Retrieve consents given for OAuth scopes by a user for user's all applications.
     *
     * @param userId    User identifier.
     * @param tenantId  Tenant Id.
     * @return  List of {@link UserApplicationScopeConsentDO}
     * @throws IdentityOAuth2ScopeConsentException
     */
    List<UserApplicationScopeConsentDO> getUserConsents(String userId, int tenantId)
            throws IdentityOAuth2ScopeConsentException;

    /**
     * Store users consent given for OAuth scopes for a given application.
     *
     * @param userId        User identifier.
     * @param tenantId      Tenant Id.
     * @param userConsent   User consent {@link UserApplicationScopeConsentDO}.
     * @throws IdentityOAuth2ScopeConsentException
     */
    void addUserConsentForApplication(String userId, int tenantId, UserApplicationScopeConsentDO userConsent)
            throws IdentityOAuth2ScopeConsentException;

    /**
     * Update users consent given for OAuth scopes for a given application.
     *
     * @param userId                User identifier.
     * @param tenantId              Tenant Id.
     * @param updatedUserConsents   Updated user consent {@link UserApplicationScopeConsentDO}.
     *
     * @deprecated use {@link #updateExistingConsentForApplication(String, String, int,
     *      UserApplicationScopeConsentDO, UserApplicationScopeConsentDO)} instead.
     *
     * Deprecated - Use
     */
    @Deprecated
    default void updateExistingConsentForApplication(String userId, int tenantId,
                                             UserApplicationScopeConsentDO updatedUserConsents)
            throws IdentityOAuth2ScopeConsentException {

    }

    /**
     * Update users consent given for OAuth scopes for a given application.
     *
     * @param userId                User identifier.
     * @param appId                 Application Id.
     * @param tenantId              Tenant Id.
     * @param consentsToBeAdded     Added user consent {@link UserApplicationScopeConsentDO}.
     * @param consentsToBeUpdated   Updated user consent {@link UserApplicationScopeConsentDO}.
     * @throws IdentityOAuth2ScopeConsentException
     */
    void updateExistingConsentForApplication(String userId, String appId, int tenantId,
                                             UserApplicationScopeConsentDO consentsToBeAdded,
                                             UserApplicationScopeConsentDO consentsToBeUpdated)
            throws IdentityOAuth2ScopeConsentException;

    /**
     * Remove user's consent given for an application.
     *
     * @param userId    User identifier.
     * @param appId     Application identifier.
     * @param tenantId  Tenant Id.
     * @throws IdentityOAuth2ScopeConsentException
     */
    void deleteUserConsentOfApplication(String userId, String appId, int tenantId)
            throws IdentityOAuth2ScopeConsentException;

    /**
     * Remove users' consent given for an application.
     *
     * @param appId     Application identifier.
     * @param tenantId  Tenant Id.
     * @throws IdentityOAuth2ScopeConsentException
     */
    default void revokeConsentOfApplication(String appId, int tenantId) throws IdentityOAuth2ScopeConsentException {

    }

    /**
     * Remove all user consents.
     *
     * @param userId    User identifier.
     * @param tenantId  Tenant Id.
     * @throws IdentityOAuth2ScopeConsentException
     */
    void deleteUserConsents(String userId, int tenantId) throws IdentityOAuth2ScopeConsentException;
}
