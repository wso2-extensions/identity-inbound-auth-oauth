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

package org.wso2.carbon.identity.oauth2.rar.dao;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsCodeDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth2.rar.dto.AuthorizationDetailsTokenDTO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

/**
 * Implements the {@link AuthorizationDetailsDAO} interface to manage rich authorization requests.
 *
 * <p> {@link AuthorizationDetailsDAO} provides methods to add, update, retrieve, and delete authorization details
 * associated with user consent and access tokens.
 */
public class AuthorizationDetailsDAOImpl implements AuthorizationDetailsDAO {

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] addUserConsentedAuthorizationDetails(
            final Set<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs) throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsConsentDTO consentDTO : authorizationDetailsConsentDTOs) {
                ps.setString(1, consentDTO.getConsentId());
                ps.setString(2, consentDTO.getAuthorizationDetail().toJsonString());
                ps.setBoolean(3, consentDTO.isConsentActive());
                ps.setString(4, consentDTO.getAuthorizationDetail().getType());
                ps.setInt(5, consentDTO.getTenantId());
                ps.setInt(6, consentDTO.getTenantId());
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }

    /**
     * {@inheritDoc}
     */
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
                    final String typeId = rs.getString(2);
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
     * {@inheritDoc}
     */
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

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] addAccessTokenAuthorizationDetails(final Set<AuthorizationDetailsTokenDTO>
                                                            authorizationDetailsTokenDTOs) throws SQLException {
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsTokenDTO tokenDTO : authorizationDetailsTokenDTOs) {
                ps.setString(1, tokenDTO.getAccessTokenId());
                ps.setString(2, tokenDTO.getAuthorizationDetail().toJsonString());
                ps.setString(3, tokenDTO.getAuthorizationDetail().getType());
                ps.setInt(4, tokenDTO.getTenantId());
                ps.setInt(5, tokenDTO.getTenantId());
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<AuthorizationDetailsTokenDTO> getAccessTokenAuthorizationDetails(final String accessTokenId,
                                                                                final int tenantId)
            throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS)) {

            ps.setString(1, accessTokenId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {

                final Set<AuthorizationDetailsTokenDTO> authorizationDetailsTokenDTO = new HashSet<>();
                while (rs.next()) {
                    final String id = rs.getString(1);
                    final String typeId = rs.getString(2);
                    final String authorizationDetail = rs.getString(3);

                    authorizationDetailsTokenDTO.add(
                            new AuthorizationDetailsTokenDTO(id, accessTokenId, typeId, authorizationDetail, tenantId));
                }
                return authorizationDetailsTokenDTO;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int deleteAccessTokenAuthorizationDetails(final String accessTokenId, final int tenantId)
            throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.DELETE_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS)) {

            ps.setString(1, accessTokenId);
            ps.setInt(2, tenantId);
            return ps.executeUpdate();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] addOAuth2CodeAuthorizationDetails(final Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs)
            throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_CODE_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsCodeDTO authorizationDetailsCodeDTO : authorizationDetailsCodeDTOs) {
                ps.setString(1, authorizationDetailsCodeDTO.getAuthorizationCodeId());
                ps.setString(2, authorizationDetailsCodeDTO.getAuthorizationDetail().toJsonString());
                ps.setString(3, authorizationDetailsCodeDTO.getAuthorizationDetail().getType());
                ps.setInt(4, authorizationDetailsCodeDTO.getTenantId());
                ps.setInt(5, authorizationDetailsCodeDTO.getTenantId());
                ps.addBatch();
            }
            return ps.executeBatch();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<AuthorizationDetailsCodeDTO> getOAuth2CodeAuthorizationDetails(final String authorizationCode,
                                                                              final int tenantId) throws SQLException {

        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_OAUTH2_CODE_AUTHORIZATION_DETAILS_BY_CODE)) {

            ps.setString(1, authorizationCode);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {

                final Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs = new HashSet<>();
                while (rs.next()) {
                    final String codeId = rs.getString(1);
                    final String typeId = rs.getString(2);
                    final String authorizationDetail = rs.getString(3);

                    authorizationDetailsCodeDTOs.add(new AuthorizationDetailsCodeDTO(
                            codeId, typeId, authorizationDetail, tenantId));
                }
                return authorizationDetailsCodeDTOs;
            }
        }
    }

    /**
     * {@inheritDoc}
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
