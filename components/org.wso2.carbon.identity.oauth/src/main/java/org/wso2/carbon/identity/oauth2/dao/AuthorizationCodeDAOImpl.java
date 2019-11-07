/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
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
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
public class AuthorizationCodeDAOImpl extends AbstractOAuthDAO implements AuthorizationCodeDAO {

    private static final Log log = LogFactory.getLog(AuthorizationCodeDAOImpl.class);

    private static final String IDN_OAUTH2_AUTHORIZATION_CODE = "IDN_OAUTH2_AUTHORIZATION_CODE";
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    @Override
    public void insertAuthorizationCode(String authzCode, String consumerKey, String callbackUrl,
                                        AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Persisting authorization code (hashed): " + DigestUtils.sha256Hex(authzCode) + " for " +
                        "client: " + consumerKey + " user: " + authzCodeDO.getAuthorizedUser().toString());
            } else {
                log.debug("Persisting authorization code for client: " + consumerKey + " user: " + authzCodeDO
                        .getAuthorizedUser().toString());
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
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                prepStmt.setString(15, authenticatedIDP);
                prepStmt.setInt(16, tenantId);
            }

            prepStmt.execute();

            AddAuthorizationCodeScopes(authzCodeDO, connection, tenantId);
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

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                StringBuilder stringBuilder = new StringBuilder();
                for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                    stringBuilder.append("Deactivating authorization code(hashed): ")
                            .append(DigestUtils.sha256Hex(authzCodeDO.getAuthorizationCode()))
                            .append(" client: ")
                            .append(authzCodeDO.getConsumerKey()).append(" user: ")
                            .append(authzCodeDO.getAuthorizedUser().toString())
                            .append("\n");
                }
                log.debug(stringBuilder.toString());
            } else {
                StringBuilder stringBuilder = new StringBuilder();
                for (AuthzCodeDO authzCodeDO : authzCodeDOs) {
                    stringBuilder.append("Deactivating authorization code client: ")
                            .append(authzCodeDO.getConsumerKey()).append(" user: ")
                            .append(authzCodeDO.getAuthorizedUser().toString())
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

            // To revoke request objects which are persisted against the code.
            OAuth2TokenUtil.postRevokeCodes(authzCodeDOs, OAuthConstants.AuthorizationCodeState.INACTIVE);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
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
            //use hash value for search
            prepStmt.setString(2, getHashingPersistenceProcessor().getProcessedAuthzCode(authorizationKey));
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
                // If the scope value is empty. It could have stored in the IDN_OAUTH2_AUTHZ_CODE_SCOPE table
                // for on demand scope migration.
                if (StringUtils.isBlank(scopeString)) {
                    List<String> scopes = getAuthorizationCodeScopes(connection, codeId, tenantId);
                    scopeString = OAuth2Util.buildScopeString(scopes.toArray(new String[0]));
                }
                AuthzCodeDO codeDo = createAuthzCodeDo(consumerKey, authorizationKey, user, codeState,
                        scopeString, callbackUrl, codeId, pkceCodeChallenge, pkceCodeChallengeMethod, issuedTime,
                        validityPeriod);
                result = new AuthorizationCodeValidationResult(codeDo, tokenId);
            }

            return result;

        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when validating an authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

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

        String authCodeStoreTable = OAuthConstants.AUTHORIZATION_CODE_STORE_TABLE;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        try {
            String sqlQuery = SQLQueries.UPDATE_AUTHORIZATION_CODE_STATE.replace(IDN_OAUTH2_AUTHORIZATION_CODE,
                    authCodeStoreTable);
            prepStmt = connection.prepareStatement(sqlQuery);
            prepStmt.setString(1, newState);
            prepStmt.setString(2, getHashingPersistenceProcessor().getProcessedAuthzCode(authzCode));
            prepStmt.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

            //If the code state is updated to inactive or expired request object which is persisted against the code
            // should be updated/removed.
            OAuth2TokenUtil.postRevokeCode(authzCode, newState, null);
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while updating the state of Authorization Code : " +
                    authzCode.toString(), e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    @Override
    public void deactivateAuthorizationCode(AuthzCodeDO authzCodeDO) throws
            IdentityOAuth2Exception {

        if (!isPersistenceEnabled()) {
            return;
        }

        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
            log.debug("Deactivating authorization code(hashed): " + DigestUtils.sha256Hex(authzCodeDO
                    .getAuthorizationCode()));

        }

        PreparedStatement prepStmt = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            prepStmt = connection.prepareStatement(SQLQueries.DEACTIVATE_AUTHZ_CODE_AND_INSERT_CURRENT_TOKEN);
            prepStmt.setString(1, authzCodeDO.getOauthTokenId());
            prepStmt.setString(2, getHashingPersistenceProcessor().getProcessedAuthzCode(authzCodeDO.getAuthorizationCode()));
            prepStmt.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);

            // To revoke the request object which is persisted against the code.
            OAuth2TokenUtil.postRevokeCode(authzCodeDO.getAuthzCodeId(), OAuthConstants.
                    AuthorizationCodeState.INACTIVE, authzCodeDO.getOauthTokenId());
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error when deactivating authorization code", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

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
            rs = ps.executeQuery();
            while (rs.next()) {
                if (isHashDisabled) {
                    authorizationCodes.add(getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1)));
                }
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting authorization codes from authorization code " +
                    "table for the application with consumer key : " + consumerKey, e);
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
            ps.setString(2, OAuthConstants.AuthorizationCodeState.ACTIVE);
            rs = ps.executeQuery();
            while (rs.next()) {
                if (isHashDisabled) {
                    authorizationCodes.add(getPersistenceProcessor().getPreprocessedAuthzCode(rs.getString(1)));
                }
            }
        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception("Error occurred while getting authorization codes from authorization code " +
                    "table for the application with consumer key : " + consumerKey, e);
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
                user.setUserName(authzUser);
                user.setUserStoreDomain(userStoreDomain);
                user.setTenantDomain(OAuth2Util.getTenantDomain(tenantId));

                // If the scope value is empty. It could have stored in the IDN_OAUTH2_AUTHZ_CODE_SCOPE table
                // for on demand scope migration.
                if (ArrayUtils.isEmpty(scope)) {
                    List<String> authorizationCodeScopes = getAuthorizationCodeScopes(connection, authzCodeId, tenantId);
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

    private void AddAuthorizationCodeScopes(AuthzCodeDO authzCodeDO, Connection connection, int tenantId) throws SQLException {

        try (PreparedStatement addScopePrepStmt = connection.prepareStatement(SQLQueries.INSERT_OAUTH2_CODE_SCOPE)) {
            String authzCodeId = authzCodeDO.getAuthzCodeId();

            if (authzCodeDO.getScope() != null && authzCodeDO.getScope().length > 0) {
                for (String scope : authzCodeDO.getScope()) {
                    addScopePrepStmt.setString(1, authzCodeId);
                    addScopePrepStmt.setString(2, scope);
                    addScopePrepStmt.setInt(3, tenantId);
                    addScopePrepStmt.addBatch();
                }
            }
            addScopePrepStmt.executeBatch();
        }
    }

    private List<String> getAuthorizationCodeScopes(Connection connection, String codeId, int tenantId) throws SQLException {

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

    private AuthzCodeDO createAuthzCodeDo(String consumerKey, String authorizationKey,
                                          AuthenticatedUser user, String codeState, String scopeString,
                                          String callbackUrl, String codeId, String pkceCodeChallenge,
                                          String pkceCodeChallengeMethod, Timestamp issuedTime, long validityPeriod) {

        return new AuthzCodeDO(user, OAuth2Util.buildScopeArray(scopeString), issuedTime, validityPeriod,
                callbackUrl, consumerKey, authorizationKey, codeId, codeState, pkceCodeChallenge,
                pkceCodeChallengeMethod);
    }
}
