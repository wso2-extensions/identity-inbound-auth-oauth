/*
 * Copyright (c) 2017-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RETRIEVE_TOKEN_BINDING_REFERENCE_TOKEN_ID;

/**
 * Authorization code data access object implementation.
 */
public class AuthorizationCodeDAOImpl extends AbstractOAuthDAO implements AuthorizationCodeDAO {

    private static final Log log = LogFactory.getLog(AuthorizationCodeDAOImpl.class);

    private static final String IDN_OAUTH2_AUTHORIZATION_CODE = "IDN_OAUTH2_AUTHORIZATION_CODE";
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    @Override
    public void insertAuthorizationCode(String authzCode, String consumerKey, String callbackUrl,
                                        AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        insertAuthorizationCode(authzCode, consumerKey,
                IdentityTenantUtil.getTenantDomain(IdentityTenantUtil.getLoginTenantId()), callbackUrl, authzCodeDO);
    }

    @Override
    public void insertAuthorizationCode(String authzCode, String consumerKey, String appTenantDomain,
                                        String callbackUrl, AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        if (!OAuth2Util.isAuthCodePersistenceEnabled()) {
            return;
        }

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Persisting authorization code (hashed): " + DigestUtils.sha256Hex(authzCode) + " for " +
                        "client: " + consumerKey + " user: " + authzCodeDO.getAuthorizedUser().getLoggableUserId());
            } else {
                log.debug("Persisting authorization code for client: " + consumerKey + " user: " + authzCodeDO
                        .getAuthorizedUser().getLoggableUserId());
            }
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        String userDomain = OAuth2Util.getUserStoreDomain(authzCodeDO.getAuthorizedUser());
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authzCodeDO.getAuthorizedUser());
        try {
            String sql;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sql = SQLQueries.STORE_AUTHORIZATION_CODE_WITH_PKCE_IDP_NAME;
            } else {
                sql = SQLQueries.STORE_AUTHORIZATION_CODE_WITH_PKCE;
            }
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, authzCodeDO.getAuthzCodeId());
            prepStmt.setString(2, getPersistenceProcessor().getProcessedAuthzCode(authzCode));
            prepStmt.setString(3, callbackUrl);
            prepStmt.setString(4, "");
            prepStmt.setString(5, authzCodeDO.getAuthorizedUser().getUserName());
            prepStmt.setString(6, userDomain);
            int tenantId = OAuth2Util.getTenantId(authzCodeDO.getAuthorizedUser().getTenantDomain());
            prepStmt.setInt(7, tenantId);
            prepStmt.setTimestamp(8, authzCodeDO.getIssuedTime(),
                    Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            prepStmt.setLong(9, authzCodeDO.getValidityPeriod());
            prepStmt.setString(10, authzCodeDO.getAuthorizedUser().getAuthenticatedSubjectIdentifier());
            prepStmt.setString(11, authzCodeDO.getPkceCodeChallenge());
            prepStmt.setString(12, authzCodeDO.getPkceCodeChallengeMethod());
            //insert the hash value of the authorization code
            prepStmt.setString(13, getHashingPersistenceProcessor().getProcessedAuthzCode(authzCode));
            prepStmt.setString(14, getPersistenceProcessor().getProcessedClientId(consumerKey));
            int appTenantId = IdentityTenantUtil.getTenantId(appTenantDomain);
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(15, authenticatedIDP);
                // Set tenant ID of the IDP by considering it is same as appTenantID.
                prepStmt.setInt(16, appTenantId);
                prepStmt.setInt(17, appTenantId);
            } else {
                prepStmt.setInt(15, appTenantId);
            }

            prepStmt.execute();

            addAuthorizationCodeScopes(authzCodeDO, connection, tenantId);
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when storing the authorization code for consumer key : " +
                    consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    @Override
    public void deactivateAuthorizationCodes(List<AuthzCodeDO> authzCodeDOs) throws IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        boolean deactivateAuthorizationCode;
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                    stringBuilder.append("Deactivating authorization code(hashed): ")
                            .append(DigestUtils.sha256Hex(authzCodeDO.getAuthorizationCode()))
                            .append(" client: ")
                            .append(authzCodeDO.getConsumerKey()).append(" user: ")
                            .append(authzCodeDO.getAuthorizedUser().getLoggableUserId())
                            .append("\n");
                }
                log.debug(stringBuilder.toString());
            } else {
                StringBuilder stringBuilder = new StringBuilder();
                for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                    stringBuilder.append("Deactivating authorization code client: ")
                            .append(authzCodeDO.getConsumerKey()).append(" user: ")
                            .append(authzCodeDO.getAuthorizedUser().getLoggableUserId())
                            .append("\n");
                }
                log.debug(stringBuilder.toString());
            }
        }
        try {
            prepStmt = connection.prepareStatement(SQLQueries.DEACTIVATE_AUTHZ_CODE_AND_INSERT_CURRENT_TOKEN);
            for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                prepStmt.setString(1, authzCodeDO.getOauthTokenId());
                prepStmt.setString(2, getHashingPersistenceProcessor()
                        .getProcessedAuthzCode(authzCodeDO.getAuthorizationCode()));
                prepStmt.addBatch();
            }
            prepStmt.executeBatch();
            IdentityDatabaseUtil.commitTransaction(connection);
            deactivateAuthorizationCode = true;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        if (deactivateAuthorizationCode) {
            // To revoke request objects which are persisted against the code.
            OAuth2TokenUtil.postRevokeCodes(authzCodeDOs, OAuthConstants.AuthorizationCodeState.INACTIVE);
        }
    }

    @Override
    public AuthorizationCodeValidationResult validateAuthorizationCode(String consumerKey, String authorizationKey)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Validating authorization code(hashed): " + DigestUtils.sha256Hex(authorizationKey)
                        + " for client: " + consumerKey);
            } else {
                log.debug("Validating authorization code for client: " + consumerKey);
            }
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        AuthorizationCodeValidationResult result = null;
        try {
            AuthenticatedUser user = null;
            String codeState = null;
            String authorizedUser = null;
            String userstoreDomain = null;
            String scopeString = null;
            String callbackUrl = null;
            String tenantDomain = null;
            String codeId = null;
            String subjectIdentifier = null;
            String pkceCodeChallenge = null;
            String pkceCodeChallengeMethod = null;

            Timestamp issuedTime = null;
            long validityPeriod = 0;
            int tenantId;

            String sql;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sql = SQLQueries.VALIDATE_AUTHZ_CODE_WITH_PKCE_IDP_NAME;
            } else {
                sql = SQLQueries.VALIDATE_AUTHZ_CODE_WITH_PKCE;
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            prepStmt.setInt(2, IdentityTenantUtil.getLoginTenantId());
            //use hash value for search
            prepStmt.setString(3, getHashingPersistenceProcessor().getProcessedAuthzCode(authorizationKey));
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                codeState = resultSet.getString(8);
                authorizedUser = resultSet.getString(1);
                userstoreDomain = resultSet.getString(2);
                tenantId = resultSet.getInt(3);
                tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                scopeString = resultSet.getString(4);
                callbackUrl = resultSet.getString(5);
                issuedTime = resultSet.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                validityPeriod = resultSet.getLong(7);
                codeId = resultSet.getString(11);
                subjectIdentifier = resultSet.getString(12);
                pkceCodeChallenge = resultSet.getString(13);
                pkceCodeChallengeMethod = resultSet.getString(14);
                String authenticatedIDP = null;
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    authenticatedIDP = resultSet.getString(15);
                }
                user = OAuth2Util.createAuthenticatedUser(authorizedUser, userstoreDomain, tenantDomain,
                        authenticatedIDP);
                ServiceProvider serviceProvider;
                try {
                    serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                            getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                } catch (IdentityApplicationManagementException e) {
                    throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data " +
                            "for client id " + consumerKey, e);
                }
                user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);

                String tokenId = resultSet.getString(9);
                String tokenBindingReference = NONE;
                if (StringUtils.isNotBlank(tokenId)) {
                    tokenBindingReference = getTokenBindingReference(connection, tokenId, tenantId);
                }
                // If the scope value is empty. It could have stored in the IDN_OAUTH2_AUTHZ_CODE_SCOPE table
                // for on demand scope migration.
                if (StringUtils.isBlank(scopeString)) {
                    List<String> scopes = getAuthorizationCodeScopes(connection, codeId, tenantId);
                    scopeString = OAuth2Util.buildScopeString(scopes.toArray(new String[0]));
                }
                AuthzCodeDO codeDo = createAuthzCodeDo(consumerKey, authorizationKey, user, codeState,
                        scopeString, callbackUrl, codeId, pkceCodeChallenge, pkceCodeChallengeMethod, issuedTime,
                        validityPeriod, tokenBindingReference);
                result = new AuthorizationCodeValidationResult(codeDo, tokenId);
            }

            return result;

        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when validating an authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    private String getTokenBindingReference(Connection connection, String tokenId, int tenantId) throws SQLException {

        try (PreparedStatement preparedStatement = connection
                .prepareStatement(RETRIEVE_TOKEN_BINDING_REFERENCE_TOKEN_ID)) {
            preparedStatement.setString(1, tokenId);
            preparedStatement.setInt(2, tenantId);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getString("TOKEN_BINDING_REF");
                }
            }
        }
        return NONE;
    }

    @Override
    public void updateAuthorizationCodeState(String authzCode, String newState) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Changing state of authorization code(hashed): " + DigestUtils.sha256Hex(authzCode)
                        + " to: " + newState);
            } else {
                log.debug("Changing state of authorization code  to: " + newState);
            }
        }
        boolean tokenUpdateSuccessful;
        String authCodeStoreTable = OAuthConstants.AUTHORIZATION_CODE_STORE_TABLE;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.UPDATE_AUTHORIZATION_CODE_STATE);
            prepStmt.setString(1, newState);
            prepStmt.setString(2, getHashingPersistenceProcessor().getProcessedAuthzCode(authzCode));
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
            tokenUpdateSuccessful = true;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while updating the state of Authorization Code : " +
                    authzCode.toString(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        if (tokenUpdateSuccessful) {
            //If the code state is updated to inactive or expired request object which is persisted against the code
            // should be updated/removed.
            OAuth2TokenUtil.postRevokeCode(authzCode, newState, null, null);
        }
    }

    @Override
    public void deactivateAuthorizationCode(AuthzCodeDO authzCodeDO) throws
            IdentityOAuth2Exception {

        if (!OAuth2Util.isAuthCodePersistenceEnabled()) {
            return;
        }

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
            log.debug("Deactivating authorization code(hashed): " + DigestUtils.sha256Hex(authzCodeDO
                    .getAuthorizationCode()));

        }
        boolean deactivateAuthorizationCode;
        PreparedStatement prepStmt = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            prepStmt = connection.prepareStatement(SQLQueries.DEACTIVATE_AUTHZ_CODE_AND_INSERT_CURRENT_TOKEN);
            prepStmt.setString(1, authzCodeDO.getOauthTokenId());
            prepStmt.setString(2,
                    getHashingPersistenceProcessor().getProcessedAuthzCode(authzCodeDO.getAuthorizationCode()));
            prepStmt.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
            deactivateAuthorizationCode = true;
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        if (deactivateAuthorizationCode) {
            // To revoke the request object which is persisted against the code.
            OAuth2TokenUtil.postRevokeCode(authzCodeDO.getAuthzCodeId(), OAuthConstants.
                    AuthorizationCodeState.INACTIVE, authzCodeDO.getOauthTokenId(), authzCodeDO.getAuthorizationCode());
        }
    }

    /**
     * Returns a list of authorization codes issued for a given user.
     *
     * @param authenticatedUser Authenticated user object.
     * @return String set of auth codes.
     * @throws IdentityOAuth2Exception If any error occurred.
     */
    @Override
    public Set<String> getAuthorizationCodesByUser(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization codes of user: " + authenticatedUser.toString());
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        try {
            String sqlQuery = SQLQueries.GET_AUTHORIZATION_CODES_BY_AUTHZUSER;
            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, authenticatedUser.getUserName());
            } else {
                ps.setString(1, authenticatedUser.getUserName().toLowerCase());
            }
            ps.setInt(2, OAuth2Util.getTenantId(authenticatedUser.getTenantDomain()));
            ps.setString(3, authenticatedUser.getUserStoreDomain());
            ps.setString(4, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();

            while (rs.next()) {
                long validityPeriodInMillis = rs.getLong(3);
                Timestamp timeCreated = rs.getTimestamp(2, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long issuedTimeInMillis = timeCreated.getTime();

                // if authorization code is not expired.
                if (OAuth2Util.calculateValidityInMillis(issuedTimeInMillis, validityPeriodInMillis) > 1000) {
                    if (isHashDisabled) {
                        authorizationCodes.add(getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1)));
                    }
                }
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking Access Token with user Name : " +
                    authenticatedUser.getUserName() + " tenant ID : " + OAuth2Util.getTenantId(authenticatedUser
                    .getTenantDomain()), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }

    /**
     * Returns the set of Authorization codes issued for the user.
     *
     * @param authenticatedUser Authenticated user object.
     * @return Authorization Codes as a list of AuthzCodeDO.
     * @throws IdentityOAuth2Exception If any errors occurred.
     */
    @Override
    public List<AuthzCodeDO> getAuthorizationCodesByUserForOpenidScope(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization codes of user: " + authenticatedUser.toString());
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs;
        List<AuthzCodeDO> authorizationCodes = new ArrayList<>();
        String authzUser = authenticatedUser.getUserName();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        try {
            String sqlQuery = SQLQueries.GET_OPEN_ID_AUTHORIZATION_CODE_DATA_BY_AUTHZUSER;
            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, authzUser);
            } else {
                ps.setString(1, authzUser.toLowerCase());
            }
            ps.setInt(2, OAuth2Util.getTenantId(tenantDomain));
            ps.setString(3, userStoreDomain);
            ps.setString(4, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();

            while (rs.next()) {
                long validityPeriodInMillis = rs.getLong(3);
                Timestamp timeCreated = rs.getTimestamp(2, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long issuedTimeInMillis = timeCreated.getTime();
                String authorizationCode = rs.getString(1);
                String authzCodeId = rs.getString(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                String callbackUrl = rs.getString(6);
                String consumerKey = rs.getString(7);
                String idpName = rs.getString(8);

                AuthenticatedUser user = OAuth2Util
                        .createAuthenticatedUser(authzUser, userStoreDomain, tenantDomain, idpName);

                //Authorization codes returned by this method will be used to clear claims cached against them.
                // We will only return authz codes that would contain such cached clams in order to improve performance.
                // Authorization codes issued for openid scope can contain cached claims against them.
                if (isAuthorizationCodeIssuedForOpenidScope(scope)) {
                    // Authorization codes that are in ACTIVE state and not expired should be removed from the cache.
                    if (OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodInMillis) > 0) {
                        if (isHashDisabled) {
                            authorizationCodes
                                    .add(new AuthzCodeDO(user, scope, timeCreated, validityPeriodInMillis, callbackUrl,
                                            consumerKey, authorizationCode, authzCodeId));
                        }
                    }
                }
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking authorization code with username : " +
                    authenticatedUser.getUserName() + " tenant ID : " + OAuth2Util.getTenantId(authenticatedUser
                    .getTenantDomain()), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }

    @Override
    public List<AuthzCodeDO> getAuthorizationCodesDataByUser(AuthenticatedUser authenticatedUser) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization codes of user: " + authenticatedUser.toString());
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs;
        List<AuthzCodeDO> authorizationCodes = new ArrayList<>();
        String authzUser = authenticatedUser.getUserName();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authenticatedUser.toString());
        try {
            String sqlQuery = SQLQueries.GET_AUTHORIZATION_CODE_DATA_BY_AUTHZUSER;
            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, authzUser);
            } else {
                ps.setString(1, authzUser.toLowerCase());
            }
            ps.setInt(2, OAuth2Util.getTenantId(tenantDomain));
            ps.setString(3, userStoreDomain);
            ps.setString(4, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            rs = ps.executeQuery();

            while (rs.next()) {
                long validityPeriodInMillis = rs.getLong(3);
                Timestamp timeCreated = rs.getTimestamp(2, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long issuedTimeInMillis = timeCreated.getTime();
                String authorizationCode = getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1));
                String authzCodeId = rs.getString(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                String callbackUrl = rs.getString(6);
                String consumerKey = rs.getString(7);


                // Authorization codes that are in ACTIVE state and not expired should be removed from the cache.
                if (OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodInMillis) > 0) {
                    if (isHashDisabled) {
                        authorizationCodes
                                .add(new AuthzCodeDO(authenticatedUser, scope, timeCreated, validityPeriodInMillis,
                                        callbackUrl, consumerKey, authorizationCode, authzCodeId));
                    }
                }
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while revoking authorization code with username : " +
                    authenticatedUser.getUserName() + " tenant ID : " + OAuth2Util.getTenantId(authenticatedUser
                    .getTenantDomain()), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }
    @Override
    public Set<String> getAuthorizationCodesByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization codes for client: " + consumerKey);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        try {
            String sqlQuery = SQLQueries.GET_AUTHORIZATION_CODES_FOR_CONSUMER_KEY;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setInt(2, IdentityTenantUtil.getLoginTenantId());
            rs = ps.executeQuery();
            while (rs.next()) {
                if (isHashDisabled) {
                    authorizationCodes.add(getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1)));
                }
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting authorization codes from authorization " +
                    "code table for the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }

    @Override
    public Set<String> getActiveAuthorizationCodesByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active authorization codes for client: " + consumerKey);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<String> authorizationCodes = new HashSet<>();
        try {
            String sqlQuery = SQLQueries.GET_ACTIVE_AUTHORIZATION_CODES_FOR_CONSUMER_KEY;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setInt(2, IdentityTenantUtil.getLoginTenantId());
            ps.setString(3, OAuthConstants.AuthorizationCodeState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                if (isHashDisabled) {
                    authorizationCodes.add(getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1)));
                }
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting authorization codes from authorization " +
                    "code table for the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
        return authorizationCodes;
    }

    @Override
    public List<AuthzCodeDO> getLatestAuthorizationCodesByTenant(int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest authorization codes of tenant id: " + tenantId);
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        List<AuthzCodeDO> latestAuthzCodes = new ArrayList<>();
        try {
            String sqlQuery;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_TENANT_IDP_NAME;
            } else {
                sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_TENANT;
            }
            ps = connection.prepareStatement(sqlQuery);
            ps.setInt(1, tenantId);
            rs = ps.executeQuery();
            while (rs.next()) {
                String authzCodeId = rs.getString(1);
                String authzCode = rs.getString(2);
                String consumerKey = rs.getString(3);
                String authzUser = rs.getString(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                Timestamp issuedTime = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = rs.getLong(7);
                String callbackUrl = rs.getString(8);
                String userStoreDomain = rs.getString(9);
                String authenticatedIDP = null;
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    authenticatedIDP = rs.getString(10);
                }

                AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain, OAuth2Util
                        .getTenantDomain(tenantId), authenticatedIDP);

                // If the scope value is empty. It could have stored in the IDN_OAUTH2_AUTHZ_CODE_SCOPE table
                // for on demand scope migration.
                if (ArrayUtils.isEmpty(scope)) {
                    List<String> authorizationCodeScopes =
                            getAuthorizationCodeScopes(connection, authzCodeId, tenantId);
                    scope = authorizationCodeScopes.toArray(new String[0]);
                }

                latestAuthzCodes.add(new AuthzCodeDO(user, scope, issuedTime, validityPeriodInMillis, callbackUrl,
                        consumerKey, authzCode, authzCodeId));
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while retrieving latest authorization codes of tenant " +
                    ":" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return latestAuthzCodes;
    }

    @Override
    public List<AuthzCodeDO> getLatestAuthorizationCodesByUserStore(int tenantId, String userStorDomain) throws
            IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving latest authorization codes of userstore: " + userStorDomain + " tenant id: " +
                    tenantId);
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement ps = null;
        ResultSet rs = null;

        String userStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(userStorDomain);

        List<AuthzCodeDO> latestAuthzCodes = new ArrayList<>();
        try {
            String sqlQuery;
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_USER_DOMAIN_IDP_NAME;
            } else {
                sqlQuery = SQLQueries.LIST_LATEST_AUTHZ_CODES_IN_USER_DOMAIN;
            }
            ps = connection.prepareStatement(sqlQuery);
            ps.setInt(1, tenantId);
            ps.setString(2, userStoreDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                String authzCodeId = rs.getString(1);
                String authzCode = rs.getString(2);
                String consumerKey = rs.getString(3);
                String authzUser = rs.getString(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                Timestamp issuedTime = rs.getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long validityPeriodInMillis = rs.getLong(7);
                String callbackUrl = rs.getString(8);
                String authenticatedIDP = null;
                if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                    authenticatedIDP = rs.getString(9);
                }

                AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authzUser, userStoreDomain, OAuth2Util
                        .getTenantDomain(tenantId), authenticatedIDP);

                // If the scope value is empty. It could have stored in the IDN_OAUTH2_AUTHZ_CODE_SCOPE table
                // for on demand scope migration.
                if (ArrayUtils.isEmpty(scope)) {
                    List<String> scopes = getAuthorizationCodeScopes(connection, authzCodeId, tenantId);
                    scope = scopes.toArray(new String[0]);
                }

                latestAuthzCodes.add(new AuthzCodeDO(user, scope, issuedTime, validityPeriodInMillis, callbackUrl,
                        consumerKey, authzCode, authzCodeId));
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while retrieving latest authorization codes of user " +
                    "store : " + userStoreDomain + " in tenant :" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return latestAuthzCodes;
    }

    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String
            newUserStoreDomain) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Renaming userstore domain: " + currentUserStoreDomain + " as: " + newUserStoreDomain
                    + " tenant id: " + tenantId + " in IDN_OAUTH2_AUTHORIZATION_CODE table");
        }
        //we do not support access token partitioning here
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        currentUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(currentUserStoreDomain);
        newUserStoreDomain = OAuth2Util.getSanitizedUserStoreDomain(newUserStoreDomain);
        try {
            String sqlQuery = SQLQueries.RENAME_USER_STORE_IN_AUTHORIZATION_CODES_TABLE;
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, newUserStoreDomain);
            ps.setInt(2, tenantId);
            ps.setString(3, currentUserStoreDomain);
            int count = ps.executeUpdate();
            if (log.isDebugEnabled()) {
                log.debug("Number of rows being updated : " + count);
            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while renaming user store : " + currentUserStoreDomain +
                    "in tenant :" + tenantId, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    private void addAuthorizationCodeScopes(AuthzCodeDO authzCodeDO, Connection connection, int tenantId)
            throws SQLException {

        try (PreparedStatement addScopePrepStmt = connection.prepareStatement(SQLQueries.INSERT_OAUTH2_CODE_SCOPE)) {
            String authzCodeId = authzCodeDO.getAuthzCodeId();
            if (authzCodeDO.getScope() != null) {
                // Get the distinct set of scopes.
                Set<String> scopes = new HashSet<>(Arrays.asList(authzCodeDO.getScope()));
                for (String scope : scopes) {
                    addScopePrepStmt.setString(1, authzCodeId);
                    addScopePrepStmt.setString(2, scope);
                    addScopePrepStmt.setInt(3, tenantId);
                    addScopePrepStmt.addBatch();
                }
            }
            addScopePrepStmt.executeBatch();
        }
    }

    private List<String> getAuthorizationCodeScopes(Connection connection, String codeId, int tenantId)
            throws SQLException {

        List<String> scopes = new ArrayList<>();
        try (PreparedStatement scopePrepStmt = connection.prepareStatement(SQLQueries.GET_OAUTH2_CODE_SCOPE)) {
            scopePrepStmt.setString(1, codeId);
            scopePrepStmt.setInt(2, tenantId);
            try (ResultSet scopesResultSet = scopePrepStmt.executeQuery()) {
                while (scopesResultSet.next()) {
                    String scope = scopesResultSet.getString(1);
                    scopes.add(scope);
                }
            }
        }
        return scopes;
    }

    private String getAuthorizationCodeByCodeId(String codeId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization code by code id: " + codeId);
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = SQLQueries.RETRIEVE_AUTHZ_CODE_BY_CODE_ID;

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, codeId);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("AUTHORIZATION_CODE");
            }
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Authorization Code' for " +
                    "authorization code : " + codeId;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    @Override
    public String getCodeIdByAuthorizationCode(String authzCode) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
            log.debug("Retrieving id of authorization code(hashed): " + DigestUtils.sha256Hex(authzCode));
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        try {
            String sql = SQLQueries.RETRIEVE_CODE_ID_BY_AUTHORIZATION_CODE;

            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getHashingPersistenceProcessor().getProcessedAuthzCode(authzCode));
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getString("CODE_ID");
            }
            return null;

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving 'Code ID' for " +
                    "authorization code : " + authzCode;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

    }

    private AuthzCodeDO createAuthzCodeDo(String consumerKey, String authorizationKey, AuthenticatedUser user,
                                          String codeState, String scopeString, String callbackUrl, String codeId,
                                          String pkceCodeChallenge, String pkceCodeChallengeMethod,
                                          Timestamp issuedTime, long validityPeriod, String tokenBindingReference) {

        return new AuthzCodeDO(user, OAuth2Util.buildScopeArray(scopeString), issuedTime, validityPeriod, callbackUrl,
                consumerKey, authorizationKey, codeId, codeState, pkceCodeChallenge, pkceCodeChallengeMethod,
                tokenBindingReference);
    }

    private boolean isActiveAuthzCodeIssuedForOidcFlow(String[] scope, long issuedTimeInMillis,
                                                       long validityPeriodInMillis) {

        return isAuthorizationCodeIssuedForOpenidScope(scope) && (
                OAuth2Util.getTimeToExpire(issuedTimeInMillis, validityPeriodInMillis) > 0);
    }

    /**
     * This method will retrieve the authorization code and code id from the IDN_OAUTH2_AUTHORIZATION_CODE table and
     * return as a dataobject.
     * @param consumerKey client id
     * @return authorization code data object
     * @throws IdentityOAuth2Exception
     */
    public Set<AuthzCodeDO> getAuthorizationCodeDOSetByConsumerKeyForOpenidScope(String consumerKey)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving active authorization code data objects for client: " + consumerKey);
        }
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        ResultSet rs = null;
        Set<AuthzCodeDO> authzCodeDOs = new HashSet<>();
        String sqlQuery = SQLQueries.GET_DETAILED_ACTIVE_AUTHORIZATION_CODES_FOR_CONSUMER_KEY;
        try {
            ps = connection.prepareStatement(sqlQuery);
            ps.setString(1, consumerKey);
            ps.setInt(2, IdentityTenantUtil.getLoginTenantId());
            ps.setString(3, OAuthConstants.AuthorizationCodeState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {

                AuthzCodeDO authzCodeDO = new AuthzCodeDO();
                String authzCode = getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1));
                String codeId = rs.getString(2);
                Timestamp timeCreated = rs.getTimestamp(3, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                long issuedTimeInMillis = timeCreated.getTime();
                long validityPeriodInMillis = rs.getLong(4);
                String[] scope = OAuth2Util.buildScopeArray(rs.getString(5));
                authzCodeDO.setAuthorizationCode(authzCode);
                authzCodeDO.setAuthzCodeId(codeId);

                if (isActiveAuthzCodeIssuedForOidcFlow(scope, issuedTimeInMillis, validityPeriodInMillis)) {
                    if (isHashDisabled) {
                        authzCodeDOs.add(authzCodeDO);
                    }
                }
            }
            connection.commit();
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollBack(connection);
            throw new IdentityOAuth2Exception(
                    "Error occurred while getting authorization codes and code ids from " + "authorization code "
                            + "table for the application with consumer key : " + consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        return authzCodeDOs;
    }

    /**
     * Checks whether the issued authorization code is for openid scope.
     *
     * @param scopes
     * @return true if authorization code issued for openid scope. False if not.
     */
    private boolean isAuthorizationCodeIssuedForOpenidScope(String[] scopes) {

        if (ArrayUtils.isNotEmpty(scopes)) {
            return Arrays.asList(scopes).contains(OAuthConstants.Scope.OPENID);
        }
        return false;
    }
}
