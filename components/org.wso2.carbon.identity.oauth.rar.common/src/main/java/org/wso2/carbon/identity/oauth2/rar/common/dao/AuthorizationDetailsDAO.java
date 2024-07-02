/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.common.dao;

import org.wso2.carbon.identity.oauth2.rar.common.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails;

import java.sql.SQLException;
import java.util.List;
import java.util.Set;

/**
 * Provides methods to interact with the database to manage authorization details.
 */
public interface AuthorizationDetailsDAO {

    /**
     * Adds authorization details against a given OAuth2 code.
     *
     * @param authorizationCodeID  The ID of the authorization code.
     * @param authorizationDetails The authorization details to store.
     * @param tenantId             The tenant ID.
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    int[] addOAuth2CodeAuthorizationDetails(String authorizationCodeID, AuthorizationDetails authorizationDetails,
                                            int tenantId) throws SQLException;

    /**
     * Adds user consented authorization details.
     *
     * @param authorizationDetailsConsentDTOs List of user consented authorization details DTOs.
     *                                        {@link AuthorizationDetailsConsentDTO }
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    int[] addUserConsentedAuthorizationDetails(List<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs)
            throws SQLException;

    int deleteUserConsentedAuthorizationDetails(String consentId, int tenantId)
            throws SQLException;

    // add a todo and mention to move this to consent module
    String getConsentIdByUserIdAndAppId(String userId, String appId, int tenantId) throws SQLException;

    Set<AuthorizationDetailsConsentDTO> getUserConsentedAuthorizationDetails(String consentId, int tenantId)
            throws SQLException;

    int[] updateUserConsentedAuthorizationDetails(List<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs)
            throws SQLException;
}
