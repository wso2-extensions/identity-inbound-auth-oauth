/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.rar.dao;

import org.wso2.carbon.identity.oauth.rar.dto.AuthorizationDetailsCodeDTO;
import org.wso2.carbon.identity.oauth.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth.rar.dto.AuthorizationDetailsTokenDTO;

import java.sql.SQLException;
import java.util.Set;

/**
 * Provides methods to interact with the database to manage rich authorization requests.
 *
 * <p> {@link AuthorizationDetailsDAO} provides methods to add, update, retrieve, and delete authorization details
 * associated with user consent and access tokens.
 */
public interface AuthorizationDetailsDAO {

    /**
     * Adds user consented authorization details to the database.
     *
     * @param authorizationDetailsConsentDTOs A set of user consented authorization details DTOs.
     *                                        {@link AuthorizationDetailsConsentDTO }
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    int[] addUserConsentedAuthorizationDetails(Set<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs)
            throws SQLException;

    /**
     * Updates user consented authorization details in the database.
     *
     * @param authorizationDetailsConsentDTOs A set of user consented authorization details DTOs.
     *                                        {@link AuthorizationDetailsConsentDTO }
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    int[] updateUserConsentedAuthorizationDetails(Set<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs)
            throws SQLException;

    /**
     * Retrieves user consented authorization details from the database.
     *
     * @param consentId The ID of the consent.
     * @param tenantId  The tenant ID.
     * @return A set of user consented authorization details DTOs.
     * @throws SQLException If a database access error occurs.
     */
    Set<AuthorizationDetailsConsentDTO> getUserConsentedAuthorizationDetails(String consentId, int tenantId)
            throws SQLException;

    /**
     * Deletes user consented authorization details from the database.
     *
     * @param consentId The ID of the consent.
     * @param tenantId  The tenant ID.
     * @return The number of rows affected by the delete operation.
     * @throws SQLException If a database access error occurs.
     */
    int deleteUserConsentedAuthorizationDetails(String consentId, int tenantId) throws SQLException;

    /**
     * Adds access token authorization details to the database.
     *
     * @param authorizationDetailsTokenDTOs A set of access token authorization details DTOs.
     *                                      {@link AuthorizationDetailsTokenDTO}
     * @return An array of integers indicating the number of rows affected for each batch operation.
     * Positive values indicate success, negative values indicate failure.
     * @throws SQLException If a database access error occurs.
     */
    int[] addAccessTokenAuthorizationDetails(Set<AuthorizationDetailsTokenDTO> authorizationDetailsTokenDTOs)
            throws SQLException;

    /**
     * Retrieves access token authorization details from the database.
     *
     * @param accessTokenId The ID of the access token.
     * @param tenantId      The tenant ID.
     * @return A set of access token authorization details DTOs.
     * @throws SQLException If a database access error occurs.
     */
    Set<AuthorizationDetailsTokenDTO> getAccessTokenAuthorizationDetails(String accessTokenId, int tenantId)
            throws SQLException;

    /**
     * Deletes access token authorization details from the database.
     *
     * @param accessTokenId The ID of the access token.
     * @param tenantId      The tenant ID.
     * @return The number of rows affected by the delete operation.
     * @throws SQLException If a database access error occurs.
     */
    int deleteAccessTokenAuthorizationDetails(String accessTokenId, int tenantId) throws SQLException;

    /**
     * Adds authorization details against a given OAuth2 code.
     *
     * @param authorizationDetailsCodeDTOs A list of code authorization details DTOs to store.
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    int[] addOAuth2CodeAuthorizationDetails(Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs)
            throws SQLException;

    /**
     * Retrieves authorization code authorization details from the database.
     *
     * @param authorizationCode The value of the authorization code.
     * @param tenantId          The tenant ID.
     * @return A set of authorization code authorization details DTOs.
     * @throws SQLException If a database access error occurs.
     */
    Set<AuthorizationDetailsCodeDTO> getOAuth2CodeAuthorizationDetails(String authorizationCode, int tenantId)
            throws SQLException;

    /**
     * Retrieves the consent ID associated with a specific user ID and application ID.
     *
     * @param userId   The user ID.
     * @param appId    The application ID.
     * @param tenantId The tenant ID.
     * @return The consent ID as a string.
     * @throws SQLException If a database access error occurs.
     */
    // TODO: Move this method to the consent module
    String getConsentIdByUserIdAndAppId(String userId, String appId, int tenantId) throws SQLException;
}
