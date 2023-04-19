/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth2;

/**
 * This service handles token revocations validations due to internal events.
 * For example token revocations due to application deletion, user deletion, client secret regeneration, user profile
 * claim updates and etc...
 */
public interface InternalRevocationEventService {

    /**
     * Add an event to the revocate a token internally.
     * @param clientId          Client ID
     * @param authorizedUser    user
     * @param tenantId          tenantId
     * @return
     */
    boolean addEvent(String clientId, String authorizedUser, String tenantId) throws IdentityOAuth2Exception ;

    /**
     * Check whether a specific token is revoked or not
     */
    boolean isTokenValid(String clientId,  String clientSecret, String grantType) throws IdentityOAuth2Exception ;

    /**
     * clean events when a user gets deleted.
     *
     * @param user  username
     * @param timestamp timestamp of the user deletion.
     * @param tenantId tenantId of the user deletion.
     * @return
     */
    boolean cleanEventsByUser(String user, String timestamp, String tenantId) throws IdentityOAuth2Exception ;

    /**
     * Clean events by tenant.
     *
     * @param tenantId  tenant Id
     * @return
     */
    boolean cleanEventsByTenant(String tenantId) throws IdentityOAuth2Exception ;
}
