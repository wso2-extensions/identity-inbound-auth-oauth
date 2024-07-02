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

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.rar.common.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetails;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Implementation of {@link AuthorizationDetailsDAO}.
 * This class provides methods to add authorization details to the database.
 */
public class AuthorizationDetailsDAOImpl implements AuthorizationDetailsDAO {

    /**
     * Stores authorization details against the provided OAuth2 authorization code.
     *
     * @param authorizationCodeID  The ID of the authorization code.
     * @param authorizationDetails The details to be added.
     * @param tenantId             The tenant ID.
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    @Override
    public int[] addOAuth2CodeAuthorizationDetails(final String authorizationCodeID,
                                                   final AuthorizationDetails authorizationDetails,
                                                   final int tenantId) throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_CODE_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetail authorizationDetail : authorizationDetails.getDetails()) {
                ps.setString(1, authorizationCodeID);
                ps.setString(2, authorizationDetail.getType());
                ps.setInt(3, tenantId);
                ps.setString(4, authorizationDetail.toJsonString());
                ps.setInt(5, tenantId);
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }

    /**
     * Stores user consented authorization details.
     *
     * @param authorizationDetailsConsentDTOs The user consented authorization details DTOs
     * @return An array of positive integers indicating the number of rows affected for each batch operation,
     * or negative integers if any of the batch operations fail.
     * @throws SQLException If a database access error occurs.
     */
    @Override
    public int[] addUserConsentedAuthorizationDetails(
            final List<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs) throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsConsentDTO consentDTO : authorizationDetailsConsentDTOs) {
                ps.setString(1, consentDTO.getConsentId());
                ps.setString(2, consentDTO.getAuthorizationDetail().getType());
                ps.setInt(3, consentDTO.getTenantId());
                ps.setString(4, consentDTO.getAuthorizationDetail().toJsonString());
                ps.setBoolean(5, consentDTO.isConsentActive());
                ps.setInt(6, consentDTO.getTenantId());
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }

    @Override
    public int[] updateUserConsentedAuthorizationDetails(
            final List<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs) throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.UPDATE_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsConsentDTO consentDTO : authorizationDetailsConsentDTOs) {
                ps.setString(1, consentDTO.getAuthorizationDetail().toJsonString());
                ps.setBoolean(2, consentDTO.isConsentActive());
                ps.setString(3, consentDTO.getConsentId());
                ps.setInt(4, consentDTO.getTenantId());
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }

    @Override
    public int deleteUserConsentedAuthorizationDetails(final String consentId, final int tenantId)
            throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.DELETE_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            ps.setString(1, consentId);
            ps.setInt(2, tenantId);
            return ps.executeUpdate();
        }
    }

    @Override
    public Set<AuthorizationDetailsConsentDTO> getUserConsentedAuthorizationDetails(final String consentId,
                                                                                    final int tenantId)
            throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            ps.setString(1, consentId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {

                final Set<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs = new HashSet<>();
                while (rs.next()) {
                    final String id = rs.getString(1);
                    final int typeId = rs.getInt(2);
                    final String authorizationDetail = rs.getString(3);
                    final boolean isConsentActive = rs.getBoolean(4);

                    authorizationDetailsConsentDTOs.add(new AuthorizationDetailsConsentDTO(id, consentId, typeId,
                            authorizationDetail, isConsentActive, tenantId));
                }
                return authorizationDetailsConsentDTOs;
            }
        }
    }

    /**
     * Retrieves the first consent ID for a given user ID and application ID.
     *
     * @param userId   The ID of the user.
     * @param appId    The ID of the application.
     * @param tenantId The tenant ID.
     * @return The first consent ID found, or null if no consent ID is found.
     * @throws SQLException If a database access error occurs.
     */
    @Override
    public String getConsentIdByUserIdAndAppId(final String userId, final String appId, final int tenantId)
            throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_IDN_OAUTH2_USER_CONSENT_CONSENT_ID)) {

            ps.setString(1, userId);
            ps.setString(2, appId);
            ps.setInt(3, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
        }
        return null;
    }
}
