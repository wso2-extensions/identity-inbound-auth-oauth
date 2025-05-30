/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.IS_EXTENDED_TOKEN;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getUserResidentTenantDomain;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isAccessTokenExtendedTableExist;

/*
NOTE
This is the very first step of moving to simplified architecture for token persistence. New set of DAO classes  for
each purpose  and factory class to get instance of each DAO classes were introduced  during  this step. Further methods
 on org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO were distributed among new set of classes, each of these method
 need to be reviewed  and refactored  during next step.
 */
/**
 * Data Access Layer functionality for Token management in OAuth 2.0 implementation. This includes
 * storing and retrieving access tokens, authorization codes and refresh tokens.
 */
public class TokenManagementDAOImpl extends AbstractOAuthDAO implements TokenManagementDAO {

    private static final Log log = LogFactory.getLog(TokenManagementDAOImpl.class);
    public static final String AUTHZ_USER = "AUTHZ_USER";
    public static final String LOWER_AUTHZ_USER = "LOWER(AUTHZ_USER)";
    private static final String UTC = "UTC";
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    private static final String IDN_OAUTH2_ACCESS_TOKEN = "IDN_OAUTH2_ACCESS_TOKEN";

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(String consumerKey, String refreshToken)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug("Validating refresh token(hashed): " + DigestUtils.sha256Hex(refreshToken) + " client: " +
                        consumerKey);
            } else {
                log.debug("Validating refresh token for client: " + consumerKey);
            }
        }

        RefreshTokenValidationDataDO validationDataDO = new RefreshTokenValidationDataDO();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql;

        try {
            String driverName = connection.getMetaData().getDriverName();
            boolean isMysqlOrMarinaDBOrH2 =
                    driverName.contains("MySQL") || driverName.contains("MariaDB") || driverName.contains("H2");
            if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                if (isAccessTokenExtendedTableExist()) {
                    if (isMysqlOrMarinaDBOrH2) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_MYSQL;
                    } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_DB2SQL;
                    } else if (driverName.contains("MS SQL")
                            || driverName.contains("Microsoft")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_MSSQL;
                    } else if (driverName.contains("PostgreSQL")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_POSTGRESQL;
                    } else if (driverName.contains("INFORMIX")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_INFORMIX;
                    } else {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_WITH_EXTENDED_ATTRIBUTES_ORACLE;
                    }
                } else {
                    if (isMysqlOrMarinaDBOrH2) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_MYSQL;
                    } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_DB2SQL;
                    } else if (driverName.contains("MS SQL")
                            || driverName.contains("Microsoft")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_MSSQL;
                    } else if (driverName.contains("PostgreSQL")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_POSTGRESQL;
                    } else if (driverName.contains("INFORMIX")) {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_INFORMIX;
                    } else {
                        sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_IDP_NAME_ORACLE;
                    }
                }
            } else {
                if (isMysqlOrMarinaDBOrH2) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_DB2SQL;
                } else if (driverName.contains("MS SQL")
                        || driverName.contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MSSQL;
                } else if (driverName.contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_POSTGRESQL;
                } else if (driverName.contains("INFORMIX")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_ORACLE;
                }
            }

            sql = OAuth2Util.getTokenPartitionedSqlByToken(sql, refreshToken);

            if (refreshToken == null) {
                sql = sql.replace("REFRESH_TOKEN = ?", "REFRESH_TOKEN IS NULL");
            }

            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, getPersistenceProcessor().getProcessedClientId(consumerKey));
            int tenantId = IdentityTenantUtil.getLoginTenantId();
            String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getApplicationResidentOrganizationId();
            /*
             If applicationResidentOrgId is not empty, then the request comes for an application which is registered
             directly in the organization of the applicationResidentOrgId. Therefore, we need to resolve the
             tenant domain of the organization to get the application tenant id.
            */
            if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
                try {
                    String tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                            .resolveTenantDomain(applicationResidentOrgId);
                    tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                } catch (OrganizationManagementException e) {
                    throw new IdentityOAuth2Exception("Error while resolving tenant domain from the organization id: "
                            + applicationResidentOrgId, e);
                }
            }
            prepStmt.setInt(2, tenantId);
            if (refreshToken != null) {
                prepStmt.setString(3, getHashingPersistenceProcessor().getProcessedRefreshToken(refreshToken));
            }

            resultSet = prepStmt.executeQuery();

            int iterateId = 0;
            List<String> scopes = new ArrayList<>();
            Map<String, String> extendedParams = new HashMap<>();
            while (resultSet.next()) {

                if (iterateId == 0) {
                    if (isHashDisabled) {
                        validationDataDO.setAccessToken(getPersistenceProcessor().getPreprocessedAccessTokenIdentifier(
                                resultSet.getString(1)));
                    } else {
                        validationDataDO.setAccessToken(resultSet.getString(1));
                    }
                    String userName = resultSet.getString(2);
                    tenantId = resultSet.getInt(3);
                    String userDomain = resultSet.getString(4);
                    String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                    validationDataDO.setRefreshToken(refreshToken);
                    validationDataDO.setScope(OAuth2Util.buildScopeArray(resultSet.getString(5)));
                    validationDataDO.setRefreshTokenState(resultSet.getString(6));
                    validationDataDO.setIssuedTime(
                            resultSet.getTimestamp(7, Calendar.getInstance(TimeZone.getTimeZone(UTC))));
                    validationDataDO.setValidityPeriodInMillis(resultSet.getLong(8));
                    validationDataDO.setTokenId(resultSet.getString(9));
                    validationDataDO.setGrantType(resultSet.getString(10));
                    String subjectIdentifier = resultSet.getString(11);
                    validationDataDO.setTokenBindingReference(resultSet.getString(12));
                    validationDataDO.setAccessTokenIssuedTime(
                            resultSet.getTimestamp(13, Calendar.getInstance(TimeZone.getTimeZone(UTC))));
                    validationDataDO.setAccessTokenValidityInMillis(resultSet.getLong(14));
                    String authorizedOrganization = resultSet.getString(15);
                    String authenticatedIDP = null;
                    if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        authenticatedIDP = resultSet.getString(16);
                    }
                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(userName, userDomain, tenantDomain,
                            authenticatedIDP);
                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier);
                    if (isAccessTokenExtendedTableExist() && resultSet.getString(17) != null &&
                            resultSet.getString(18) != null) {
                        extendedParams.put(resultSet.getString(17), resultSet.getString(18));
                    }
                    // For B2B users, the users tenant domain and user resident organization should be properly set.
                    if (!OAuthConstants.AuthorizedOrganization.NONE.equals(authorizedOrganization)) {
                        user.setAccessingOrganization(authorizedOrganization);
                        user.setUserResidentOrganization(resolveOrganizationId(user.getTenantDomain()));
                        /* Setting user's tenant domain as app residing tenant domain is not required once console is
                            registered in each tenant. */
                        String appResideOrg = getAppTenantDomain();
                        if (StringUtils.isNotEmpty(appResideOrg) && user.isFederatedUser()) {
                            user.setTenantDomain(appResideOrg);
                        }
                    }
                    validationDataDO.setAuthorizedUser(user);

                } else {
                    if (!scopes.contains(resultSet.getString(5)) &&
                            !validationDataDO.getScope()[0].equals(resultSet.getString(5))) {
                        scopes.add(resultSet.getString(5));
                    }
                    if (isAccessTokenExtendedTableExist() && resultSet.getString(17) != null &&
                            resultSet.getString(18) != null) {
                        extendedParams.put(resultSet.getString(17), resultSet.getString(18));
                    }
                }

                iterateId++;
            }

            if (scopes.size() > 0 && validationDataDO != null) {
                validationDataDO.setScope((String[]) ArrayUtils.addAll(validationDataDO.getScope(),
                        scopes.toArray(new String[scopes.size()])));
            }

            if (extendedParams.size() > 0) {
                extendedParams.remove(IS_EXTENDED_TOKEN);
                validationDataDO.setAccessTokenExtendedAttributes(new AccessTokenExtendedAttributes(extendedParams));
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error when validating a refresh token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return validationDataDO;
    }

    @Override
    public AccessTokenDO getRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                log.debug("Validating refresh token(hashed): " + DigestUtils.sha256Hex(refreshToken));
            }
        }

        AccessTokenDO validationDataDO = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        String sql;
        if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
            sql = SQLQueries.RETRIEVE_REFRESH_TOKEN_WITH_IDP_NAME;
        } else {
            sql = SQLQueries.RETRIEVE_REFRESH_TOKEN;
        }

        try {
            sql = OAuth2Util.getTokenPartitionedSqlByToken(sql, refreshToken);
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, getHashingPersistenceProcessor().getProcessedRefreshToken(refreshToken));
            resultSet = prepStmt.executeQuery();

            int iterateId = 0;
            List<String> scopes = new ArrayList<>();
            while (resultSet.next()) {
                if (iterateId == 0) {
                    String consumerKey = getPersistenceProcessor().getPreprocessedClientId(resultSet.getString(1));
                    String authorizedUser = resultSet.getString(2);
                    int tenantId = resultSet.getInt(3);
                    String tenantDomain = OAuth2Util.getTenantDomain(tenantId);
                    String userDomain = resultSet.getString(4);
                    String[] scope = OAuth2Util.buildScopeArray(resultSet.getString(5));
                    Timestamp accessTokenIssuedTime = resultSet
                            .getTimestamp(6, Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    Timestamp refreshTokenIssuedTime = resultSet.getTimestamp(7,
                            Calendar.getInstance(TimeZone.getTimeZone(UTC)));
                    long validityPeriodInMillis = resultSet.getLong(8);
                    long refreshTokenValidityPeriodMillis = resultSet.getLong(9);
                    String tokenType = resultSet.getString(10);
                    String accessTokenIdentifier = resultSet.getString(11);
                    String tokenId = resultSet.getString(12);
                    String grantType = resultSet.getString(13);
                    String subjectIdentifier = resultSet.getString(14);
                    String authenticatedIDP = null;
                    if (OAuth2ServiceComponentHolder.isIDPIdColumnEnabled()) {
                        authenticatedIDP = resultSet.getString(15);
                    }

                    AuthenticatedUser user = OAuth2Util.createAuthenticatedUser(authorizedUser, userDomain,
                            tenantDomain, authenticatedIDP);

                    ServiceProvider serviceProvider;
                    try {
                        serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                getServiceProviderByClientId(consumerKey, OAuthConstants.Scope.OAUTH2, tenantDomain);
                    } catch (IdentityApplicationManagementException e) {
                        throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data " +
                                "for client id " + consumerKey, e);
                    }

                    user.setAuthenticatedSubjectIdentifier(subjectIdentifier, serviceProvider);

                    validationDataDO = new AccessTokenDO(consumerKey, user, scope, accessTokenIssuedTime,
                            refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodMillis,
                            tokenType);
                    validationDataDO.setAccessToken(accessTokenIdentifier);
                    validationDataDO.setTokenId(tokenId);
                    validationDataDO.setGrantType(grantType);
                    validationDataDO.setTenantID(tenantId);
                    validationDataDO.setRefreshToken(refreshToken);
                } else {
                    scopes.add(resultSet.getString(5));
                }
                iterateId++;
            }
            if (scopes.size() > 0 && validationDataDO != null) {
                validationDataDO.setScope((String[]) ArrayUtils.addAll(validationDataDO.getScope(),
                        scopes.toArray(new String[scopes.size()])));
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving Refresh Token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return validationDataDO;
    }

    /**
     * This method is to get resource scope key and tenant id of the resource uri
     *
     * @param resourceUri Resource Path
     * @return Pair which contains resource scope key and the tenant id
     * @throws IdentityOAuth2Exception if failed to find the tenant and resource scope
     */
    @Override
    public Pair<String, Integer> findTenantAndScopeOfResource(String resourceUri) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving tenant and scope for resource: " + resourceUri);
        }
        String sql;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {

            if (connection.getMetaData().getDriverName().contains(Oauth2ScopeConstants.DataBaseType.ORACLE)) {
                sql = SQLQueries.RETRIEVE_SCOPE_WITH_TENANT_FOR_RESOURCE_ORACLE;
            } else {
                sql = SQLQueries.RETRIEVE_SCOPE_WITH_TENANT_FOR_RESOURCE;
            }

            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, resourceUri);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        String scopeName = rs.getString("NAME");
                        int tenantId = rs.getInt("TENANT_ID");
                        if (log.isDebugEnabled()) {
                            log.debug("Found tenant id: " + tenantId + " and scope: " + scopeName + " for resource: " +
                                    resourceUri);
                        }
                        return Pair.of(scopeName, tenantId);
                    }
                }
            }
            return null;
        } catch (SQLException e) {
            String errorMsg = "Error getting scopes for resource - " + resourceUri;
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Revoke the OAuth Consent which is recorded in the IDN_OPENID_USER_RPS table against the user for a particular
     * Application
     *
     * @param username        - Username of the Consent owner
     * @param applicationName - Name of the OAuth App
     * @throws IdentityOAuth2Exception - If an unexpected error occurs.
     */
    public void revokeOAuthConsentByApplicationAndUser(String username, String applicationName)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking OAuth consent for application: " + applicationName + " by user: " + username);
        }

        if (username == null || applicationName == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not remove consent of user " + username + " for application " + applicationName);
            }
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            String sql = SQLQueries.DELETE_USER_RPS;

            ps = connection.prepareStatement(sql);
            ps.setString(1, username);
            ps.setString(2, applicationName);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String errorMsg =
                    "Error deleting OAuth consent of Application " + applicationName + " and User " + username;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Revoke the OAuth Consent which is recorded in the IDN_OPENID_USER_RPS table against the user for a particular
     * Application
     *
     * @param username        - Username of the Consent owner
     * @param applicationName - Name of the OAuth App
     * @throws IdentityOAuth2Exception - If an unexpected error occurs.
     */
    @Override
    public void revokeOAuthConsentByApplicationAndUser(String username, String tenantDomain, String applicationName)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking OAuth consent for application: " + applicationName + " by user: " + username + " " +
                    "tenant: " + tenantDomain);
        }

        if (username == null || applicationName == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not remove consent of user " + username + " for application " + applicationName);
            }
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            String sql = SQLQueries.DELETE_USER_RPS_IN_TENANT;

            ps = connection.prepareStatement(sql);
            ps.setString(1, username);
            ps.setInt(2, IdentityTenantUtil.getTenantId(tenantDomain));
            ps.setString(3, applicationName);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String errorMsg = "Error deleting OAuth consent of Application " +
                    applicationName + " and User " + username;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * Revoke the OAuth consents by the application name and tenant domain.
     *
     * @param applicationName Name of the OAuth application
     * @param tenantDomain    Tenant domain of the application
     * @throws IdentityOAuth2Exception If an unexpected error occurs
     */
    @Override
    public void revokeOAuthConsentsByApplication(String applicationName, String tenantDomain)
            throws IdentityOAuth2Exception {

        // TODO: Modify the functionality to revoke all OAuth consents of SaaS applications.
        if (log.isDebugEnabled()) {
            String message = String.format("Revoking all OAuth consents given for application: %s in " +
                    "tenant domain: %s.", applicationName, tenantDomain);
            log.debug(message);
        }

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {
            try (PreparedStatement ps = connection.prepareStatement(SQLQueries.DELETE_USER_RPS_OF_APPLICATION)) {
                ps.setInt(1, tenantId);
                ps.setString(2, applicationName);
                ps.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            }
        } catch (SQLException e) {
            String errorMsg = String.format("Error revoking all OAuth consents given for application: %s in " +
                    "tenant domain: %s.", applicationName, tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, e);
        }
    }

    /**
     * Update the OAuth Consent Approve Always which is recorded in the IDN_OPENID_USER_RPS table against
     * the user for a particular Application
     *
     * @param tenantAwareUserName - Username of the Consent owner
     * @param applicationName     - Name of the OAuth App
     * @throws IdentityOAuth2Exception - If an unexpected error occurs.
     */
    @Override
    public void updateApproveAlwaysForAppConsentByResourceOwner(String tenantAwareUserName, String tenantDomain,
                                                                String applicationName, String state)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Setting consent for " + state + " OAuth consent for application: " + applicationName + " by " +
                    "user: " + tenantAwareUserName + " tenant: " + tenantDomain);
        }

        if (tenantAwareUserName == null || applicationName == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not remove consent of user " + tenantAwareUserName +
                        " for application " + applicationName);
            }
            return;
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;

        try {
            String sql = SQLQueries.UPDATE_TRUSTED_ALWAYS_IDN_OPENID_USER_RPS;

            ps = connection.prepareStatement(sql);
            ps.setString(1, state);
            ps.setString(2, tenantAwareUserName);
            ps.setInt(3, IdentityTenantUtil.getTenantId(tenantDomain));
            ps.setString(4, applicationName);
            ps.execute();
            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            String errorMsg = "Error updating trusted always in a consent of Application " +
                    applicationName + " and User " + tenantAwareUserName;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    //TODO
    @Override
    public void updateAppAndRevokeTokensAndAuthzCodes(String consumerKey, Properties properties,
                                                      String[] authorizationCodes, String[] accessTokens)
            throws IdentityOAuth2Exception, IdentityApplicationManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Updating state of client: " + consumerKey + " and revoking all access tokens and " +
                    "authorization codes.");
        }

        String action;
        if (properties.containsKey(OAuthConstants.ACTION_PROPERTY_KEY)) {
            action = properties.getProperty(OAuthConstants.ACTION_PROPERTY_KEY);
        } else {
            throw new IdentityOAuth2Exception("Invalid operation.");
        }

        Connection connection = null;
        PreparedStatement updateStateStatement = null;
        PreparedStatement revokeActiveTokensStatement = null;
        PreparedStatement deactivateActiveCodesStatement = null;
        int appTenantId = IdentityTenantUtil.getLoginTenantId();
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            if (OAuthConstants.ACTION_REVOKE.equals(action)) {
                String newAppState;
                if (properties.containsKey(OAuthConstants.OAUTH_APP_NEW_STATE)) {
                    newAppState = properties.getProperty(OAuthConstants.OAUTH_APP_NEW_STATE);
                } else {
                    throw new IdentityOAuth2Exception("New App State is not specified.");
                }

                if (log.isDebugEnabled()) {
                    log.debug("Changing the state of the client: " + consumerKey + " to " + newAppState + " state.");
                }

                // update application state of the oauth app
                updateStateStatement = connection.prepareStatement
                        (org.wso2.carbon.identity.oauth.dao.SQLQueries.OAuthAppDAOSQLQueries.UPDATE_APPLICATION_STATE);
                updateStateStatement.setString(1, newAppState);
                updateStateStatement.setString(2, consumerKey);
                updateStateStatement.setInt(3, appTenantId);
                updateStateStatement.execute();

            } else if (OAuthConstants.ACTION_REGENERATE.equals(action)) {
                String newSecretKey;
                if (properties.containsKey(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY)) {
                    newSecretKey = properties.getProperty(OAuthConstants.OAUTH_APP_NEW_SECRET_KEY);
                } else {
                    throw new IdentityOAuth2Exception("New Consumer Secret is not specified.");
                }

                if (properties.containsKey(OAuthConstants.OAUTH_APP_NEW_STATE)) {
                    // Update the consumer secret of the oauth app when the new app state is available.
                    updateStateStatement = connection.prepareStatement
                            (org.wso2.carbon.identity.oauth.dao.SQLQueries.OAuthAppDAOSQLQueries.
                                    UPDATE_OAUTH_SECRET_KEY_AND_STATE);
                    updateStateStatement.setString(1, getPersistenceProcessor().getProcessedClientSecret(newSecretKey));
                    updateStateStatement.setString(2, properties.getProperty(OAuthConstants.OAUTH_APP_NEW_STATE));
                    updateStateStatement.setString(3, consumerKey);
                    updateStateStatement.setInt(4, appTenantId);
                } else {
                    // Update the consumer secret of the oauth app when the new app state is not available.
                    updateStateStatement = connection.prepareStatement
                            (org.wso2.carbon.identity.oauth.dao.SQLQueries.OAuthAppDAOSQLQueries.
                                    UPDATE_OAUTH_SECRET_KEY);
                    updateStateStatement.setString(1, getPersistenceProcessor().getProcessedClientSecret(newSecretKey));
                    updateStateStatement.setString(2, consumerKey);
                    updateStateStatement.setInt(3, appTenantId);
                }
                updateStateStatement.execute();

                if (log.isDebugEnabled()) {
                    log.debug("Regenerating the client secret of: " + consumerKey);
                }
            }

            //Revoke all active access tokens
            if (ArrayUtils.isNotEmpty(accessTokens)) {
                if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
                    for (String token : accessTokens) {
                        String sqlQuery = OAuth2Util.getTokenPartitionedSqlByToken(SQLQueries.REVOKE_APP_ACCESS_TOKEN,
                                token);

                        revokeActiveTokensStatement = connection.prepareStatement(sqlQuery);
                        revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                        revokeActiveTokensStatement.setString(2, UUID.randomUUID().toString());
                        revokeActiveTokensStatement.setString(3, consumerKey);
                        revokeActiveTokensStatement.setInt(4, appTenantId);
                        int count = revokeActiveTokensStatement.executeUpdate();
                        if (log.isDebugEnabled()) {
                            log.debug("Number of rows being updated : " + count);
                        }
                    }
                } else {
                    revokeActiveTokensStatement = connection.prepareStatement(SQLQueries.REVOKE_APP_ACCESS_TOKEN);
                    revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                    revokeActiveTokensStatement.setString(2, UUID.randomUUID().toString());
                    revokeActiveTokensStatement.setString(3, consumerKey);
                    revokeActiveTokensStatement.setInt(4, appTenantId);
                    revokeActiveTokensStatement.setString(5, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
                    revokeActiveTokensStatement.execute();
                }
            }

            //Deactivate all active authorization codes
            String sqlQuery = SQLQueries.UPDATE_AUTHORIZATION_CODE_STATE_FOR_CONSUMER_KEY;
            deactivateActiveCodesStatement = connection.prepareStatement(sqlQuery);
            deactivateActiveCodesStatement.setString(1, OAuthConstants.AuthorizationCodeState.REVOKED);
            deactivateActiveCodesStatement.setString(2, consumerKey);
            deactivateActiveCodesStatement.setInt(3, appTenantId);
            deactivateActiveCodesStatement.executeUpdate();

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        } finally {
            IdentityDatabaseUtil.closeStatement(updateStateStatement);
            IdentityDatabaseUtil.closeStatement(revokeActiveTokensStatement);
            IdentityDatabaseUtil.closeAllConnections(connection, null, deactivateActiveCodesStatement);
        }
    }

    /**
     * Revoke active access tokens issued against application.
     *
     * @param consumerKey    OAuth application consumer key.
     * @param accessTokens   Active access tokens.
     * @throws IdentityOAuth2Exception
     * @throws IdentityApplicationManagementException
     */
    @Override
    public void revokeTokens(String consumerKey, String[] accessTokens)
            throws IdentityOAuth2Exception, IdentityApplicationManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Updating state of client: " + consumerKey + " and revoking all access tokens.");
        }
        int appTenantId = IdentityTenantUtil.getLoginTenantId();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            //Revoke all active access tokens
            if (ArrayUtils.isNotEmpty(accessTokens)) {
                if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
                    for (String token : accessTokens) {
                        String sqlQuery = OAuth2Util.getTokenPartitionedSqlByToken(SQLQueries.REVOKE_APP_ACCESS_TOKEN,
                                token);
                        try (PreparedStatement revokeActiveTokensStatement = connection.prepareStatement(sqlQuery)) {
                            revokeActiveTokensStatement.setString(1,
                                    OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
                            revokeActiveTokensStatement.setString(2, UUID.randomUUID().toString());
                            revokeActiveTokensStatement.setString(3, consumerKey);
                            revokeActiveTokensStatement.setInt(4, appTenantId);
                            int count = revokeActiveTokensStatement.executeUpdate();
                            if (log.isDebugEnabled()) {
                                log.debug("Number of rows being updated : " + count);
                            }
                        }
                    }
                } else {
                    try (PreparedStatement revokeActiveTokensStatement = connection.prepareStatement(SQLQueries.
                            REVOKE_APP_ACCESS_TOKEN)) {
                        revokeActiveTokensStatement.setString(1, OAuthConstants.TokenStates.
                                TOKEN_STATE_REVOKED);
                        revokeActiveTokensStatement.setString(2, UUID.randomUUID().toString());
                        revokeActiveTokensStatement.setString(3, consumerKey);
                        revokeActiveTokensStatement.setInt(4, appTenantId);
                        revokeActiveTokensStatement.setString(5, OAuthConstants.TokenStates.
                                TOKEN_STATE_ACTIVE);
                        revokeActiveTokensStatement.execute();
                    }
                }
            }
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while revoking access tokens. ", e);
        }
    }

    /**
     * Revoke authorize codes issued against application.
     *
     * @param consumerKey          OAuth application consumer key.
     * @param authorizationCodes   Active authorization codes.
     * @throws IdentityApplicationManagementException
     */
    @Override
    public void revokeAuthzCodes(String consumerKey, String[] authorizationCodes)
            throws IdentityApplicationManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Updating state of client: " + consumerKey + " and revoking all authorization codes.");
        }
        int appTenantId = IdentityTenantUtil.getLoginTenantId();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement deactivateActiveCodesStatement =
                         connection.prepareStatement(SQLQueries.UPDATE_AUTHORIZATION_CODE_STATE_FOR_CONSUMER_KEY)) {
                //Deactivate all active authorization codes
                deactivateActiveCodesStatement.setString(1, OAuthConstants.AuthorizationCodeState.REVOKED);
                deactivateActiveCodesStatement.setString(2, consumerKey);
                deactivateActiveCodesStatement.setInt(3, appTenantId);
                deactivateActiveCodesStatement.executeUpdate();
                IdentityDatabaseUtil.commitTransaction(connection);
            }
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while revoking authz codes.", e);
        }
    }

    /**
     * Revokes access tokens issued against specified consumer key and specified tenant id when SaaS is disabled.
     *
     * @param consumerKey client ID
     * @param tenantId    application tenant ID
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void revokeSaaSTokensOfOtherTenants(String consumerKey, int tenantId) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking access tokens of client: " + consumerKey + " tenant id: " + tenantId + " issued for " +
                    "other tenants");
        }

        if (consumerKey == null) {
            if (log.isDebugEnabled()) {
                log.debug("Couldn't revoke token for tenant ID: " + tenantId + " because of null consumer key");
            }
            return;
        }

        revokeSaaSTokensOfOtherTenants(consumerKey, IdentityUtil.getPrimaryDomainName(), tenantId);

        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            Map<String, String> availableDomainMappings = OAuth2Util.getAvailableUserStoreDomainMappings();
            for (Map.Entry<String, String> availableDomainMapping : availableDomainMappings.entrySet()) {
                revokeSaaSTokensOfOtherTenants(consumerKey, availableDomainMapping.getKey(), tenantId);
            }
        }
    }

    /**
     * Revokes access tokens issued against specified consumer key, specified user store & specified tenant id when SaaS
     * is disabled.
     *
     * @param consumerKey
     * @param userStoreDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void revokeSaaSTokensOfOtherTenants(String consumerKey, String userStoreDomain, int tenantId) throws
            IdentityOAuth2Exception {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement ps = null;
        try {
            String sql = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.REVOKE_SAAS_TOKENS_OF_OTHER_TENANTS,
                    userStoreDomain);
            ps = connection.prepareStatement(sql);
            ps.setString(1, OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            ps.setString(2, UUID.randomUUID().toString());
            ps.setString(3, OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            ps.setString(4, consumerKey);
            ps.setInt(5, tenantId);
            ps.setInt(6, IdentityTenantUtil.getLoginTenantId());
            ps.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            String errorMsg = "Error revoking access tokens for client ID: "
                    + consumerKey + "and tenant ID:" + tenantId;
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, ps);
        }
    }

    /**
     * This method is to list the application authorized by OAuth resource owners
     *
     * @param authzUser username of the resource owner
     * @return set of distinct client IDs authorized by user until now
     * @throws IdentityOAuth2Exception if failed to update the access token
     */
    @Override
    public Set<String> getAllTimeAuthorizedClientIds(AuthenticatedUser authzUser) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving all authorized clients by user: " + authzUser.toString());
        }

        PreparedStatement ps = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        ResultSet rs = null;
        Set<String> distinctConsumerKeys = new HashSet<>();
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authzUser.toString());
        String tenantDomain = getUserResidentTenantDomain(authzUser);
        String tenantAwareUsernameWithNoUserDomain = authzUser.getUserName();
        String userDomain = OAuth2Util.getSanitizedUserStoreDomain(authzUser.getUserStoreDomain());
        if (log.isDebugEnabled()) {
            log.debug("Obtain the User's(" + tenantAwareUsernameWithNoUserDomain + ") tenant domain: " + tenantDomain
                    + "/" + OAuth2Util.getTenantId(tenantDomain) + "and user-domain: " + userDomain);
        }
        try {
            int tenantId = OAuth2Util.getTenantId(tenantDomain);

            String sqlQuery = OAuth2Util.getTokenPartitionedSqlByUserStore(SQLQueries.
                    GET_DISTINCT_APPS_AUTHORIZED_BY_USER_ALL_TIME, authzUser.getUserStoreDomain());

            if (!isUsernameCaseSensitive) {
                sqlQuery = sqlQuery.replace(AUTHZ_USER, LOWER_AUTHZ_USER);
            }
            ps = connection.prepareStatement(sqlQuery);
            if (isUsernameCaseSensitive) {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain);
            } else {
                ps.setString(1, tenantAwareUsernameWithNoUserDomain.toLowerCase());
            }
            ps.setInt(2, tenantId);
            ps.setString(3, userDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                String consumerKey = getPersistenceProcessor().getPreprocessedClientId(rs.getString(1));
                distinctConsumerKeys.add(consumerKey);
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while retrieving all distinct Client IDs authorized by " +
                            "User ID : " + authzUser + " until now", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs, ps);
        }
        if (log.isDebugEnabled()) {
            StringBuilder consumerKeys = new StringBuilder();
            for (String consumerKey : distinctConsumerKeys) {
                consumerKeys.append(consumerKey).append(" ");
            }
            log.debug("Found authorized clients " + consumerKeys.toString() + " for user: " + authzUser.toString());
        }
        return distinctConsumerKeys;
    }

    private String getAppTenantDomain() {

        return IdentityTenantUtil.getTenantDomainFromContext();
    }

    private String resolveOrganizationId(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while resolving organization ID for the tenant domain: " +
                    tenantDomain, e);
        }
    }
}
