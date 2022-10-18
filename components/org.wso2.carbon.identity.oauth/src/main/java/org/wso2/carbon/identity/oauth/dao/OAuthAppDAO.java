/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dao;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.Error;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.IdentityOAuthClientException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DBUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.BACK_CHANNEL_LOGOUT_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.BYPASS_CLIENT_CREDENTIALS;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.FRONT_CHANNEL_LOGOUT_URL;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.ID_TOKEN_ENCRYPTED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.ID_TOKEN_ENCRYPTION_ALGORITHM;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.ID_TOKEN_ENCRYPTION_METHOD;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.RENEW_REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.REQUEST_OBJECT_SIGNED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.TOKEN_BINDING_TYPE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.TOKEN_BINDING_TYPE_NONE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.TOKEN_BINDING_VALIDATION;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.TOKEN_REVOCATION_WITH_IDP_SESSION_TERMINATION;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OIDCConfigProperties.TOKEN_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.OPENID_CONNECT_ACCESS_TOKEN_AUDIENCE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.OPENID_CONNECT_AUDIENCE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.OPENID_CONNECT_ID_TOKEN_AUDIENCE;



/**
 * JDBC Based data access layer for OAuth Consumer Applications.
 */
public class OAuthAppDAO {

    private static final Log LOG = LogFactory.getLog(OAuthAppDAO.class);
    private static final String APP_STATE = "APP_STATE";
    private static final String USERNAME = "USERNAME";
    private static final String LOWER_USERNAME = "LOWER(USERNAME)";
    private static final String CONSUMER_KEY_CONSTRAINT = "CONSUMER_KEY_CONSTRAINT";

    private TokenPersistenceProcessor persistenceProcessor;
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    public OAuthAppDAO() {

        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextPersistenceProcessor");
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }

    }

    public void addOAuthApplication(OAuthAppDO consumerAppDO) throws IdentityOAuthAdminException {

        AuthenticatedUser appOwner = consumerAppDO.getAppOwner();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        int spTenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String userStoreDomain = appOwner.getUserStoreDomain();
        if (!isDuplicateApplication(appOwner.getUserName(), spTenantId, userStoreDomain, consumerAppDO)) {
            int appId = 0;
            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
                try {
                    String processedClientId =
                            persistenceProcessor.getProcessedClientId(consumerAppDO.getOauthConsumerKey());
                    String processedClientSecret =
                            persistenceProcessor.getProcessedClientSecret(consumerAppDO.getOauthConsumerSecret());

                    String dbProductName = connection.getMetaData().getDatabaseProductName();
                    try (PreparedStatement prepStmt = connection
                            .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP_WITH_PKCE, new String[] {
                                    DBUtils.getConvertedAutoGeneratedColumnName(dbProductName, "ID")
                            })) {
                        prepStmt.setString(1, processedClientId);
                        prepStmt.setString(2, processedClientSecret);
                        prepStmt.setString(3, appOwner.getUserName());
                        prepStmt.setInt(4, spTenantId);
                        prepStmt.setString(5, userStoreDomain);
                        prepStmt.setString(6, consumerAppDO.getApplicationName());
                        prepStmt.setString(7, consumerAppDO.getOauthVersion());
                        prepStmt.setString(8, consumerAppDO.getCallbackUrl());
                        prepStmt.setString(9, consumerAppDO.getGrantTypes());
                        prepStmt.setString(10, consumerAppDO.isPkceMandatory() ? "1" : "0");
                        prepStmt.setString(11, consumerAppDO.isPkceSupportPlain() ? "1" : "0");
                        prepStmt.setLong(12, consumerAppDO.getUserAccessTokenExpiryTime());
                        prepStmt.setLong(13, consumerAppDO.getApplicationAccessTokenExpiryTime());
                        prepStmt.setLong(14, consumerAppDO.getRefreshTokenExpiryTime());
                        prepStmt.setLong(15, consumerAppDO.getIdTokenExpiryTime());
                        prepStmt.execute();
                        try (ResultSet results = prepStmt.getGeneratedKeys()) {
                            if (results.next()) {
                                appId = results.getInt(1);
                            }
                        }
                    }

                    // Some JDBC Drivers returns this in the result, some don't so need to check before continuing.
                    if (appId == 0) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "JDBC Driver did not returning the app id of the newly created app " + consumerAppDO
                                            .getApplicationName() + ". So executing select operation to get the id");
                        }
                        appId = getAppIdByClientId(connection, consumerAppDO.getOauthConsumerKey());
                    }
                    addScopeValidators(connection, appId, consumerAppDO.getScopeValidators());
                    // Handle OIDC Related Properties. These are persisted in IDN_OIDC_PROPERTY table.
                    addServiceProviderOIDCProperties(connection, consumerAppDO, processedClientId, spTenantId);
                    IdentityDatabaseUtil.commitTransaction(connection);
                } catch (SQLException e1) {
                    IdentityDatabaseUtil.rollbackTransaction(connection);
                    if (isDuplicateClient(e1)) {
                        String msg = "An application with the same clientId already exists.";
                        throw new IdentityOAuthClientException(Error.DUPLICATE_OAUTH_CLIENT.getErrorCode(), msg, e1);
                    }
                    throw handleError(String.format("Error when executing SQL to create OAuth app %s@%s ",
                            consumerAppDO.getApplicationName(), appOwner.getTenantDomain()), e1);
                }
            } catch (SQLException e) {
                throw handleError(String.format("Error when executing SQL to create OAuth app %s@%s ",
                        consumerAppDO.getApplicationName(), appOwner.getTenantDomain()), e);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error occurred while processing the client id and client secret by " +
                        "TokenPersistenceProcessor", null);
            } catch (InvalidOAuthClientException e) {
                throw handleError("Error occurred while processing client id", e);
            }
        } else {
            String msg = "An application with the same name already exists.";
            throw new IdentityOAuthClientException(Error.DUPLICATE_OAUTH_CLIENT.getErrorCode(), msg);
        }
    }

    private boolean isDuplicateClient(SQLException e) {
        // We detect constraint violations in JDBC drivers which don't throw SQLIntegrityConstraintViolationException
        // by looking at the error message.
        return e instanceof SQLIntegrityConstraintViolationException ||
                StringUtils.containsIgnoreCase(e.getMessage(), CONSUMER_KEY_CONSTRAINT);
    }

    public String[] addOAuthConsumer(String username, int tenantId, String userDomain) throws
            IdentityOAuthAdminException {
        String consumerKey;
        String consumerSecret = OAuthUtil.getRandomNumber();
        long userAccessTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getUserAccessTokenValidityPeriodInSeconds();
        long applicationAccessTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getApplicationAccessTokenValidityPeriodInSeconds();
        long refreshTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getRefreshTokenValidityPeriodInSeconds();
        long idTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getOpenIDConnectIDTokenExpiryTimeInSeconds();

        do {
            consumerKey = OAuthUtil.getRandomNumber();
        }
        while (isDuplicateConsumer(consumerKey));

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER)) {
                prepStmt.setString(1, consumerKey);
                prepStmt.setString(2, consumerSecret);
                prepStmt.setString(3, username);
                prepStmt.setInt(4, tenantId);
                prepStmt.setString(5, userDomain);
                // it is assumed that the OAuth version is 1.0a because this is required with OAuth 1.0a
                prepStmt.setString(6, OAuthConstants.OAuthVersions.VERSION_1A);
                prepStmt.setLong(7, userAccessTokenExpireTime);
                prepStmt.setLong(8, applicationAccessTokenExpireTime);
                prepStmt.setLong(9, refreshTokenExpireTime);
                prepStmt.setLong(10, idTokenExpireTime);
                prepStmt.execute();

                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                String sqlStmt = SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER;
                throw handleError("Error when executing the SQL : " + sqlStmt, e1);
            }
        } catch (SQLException e) {
            String sqlStmt = SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER;
            throw handleError("Error when executing the SQL : " + sqlStmt, e);
        }
        return new String[]{consumerKey, consumerSecret};
    }

    public OAuthAppDO[] getOAuthConsumerAppsOfUser(String username, int tenantId) throws IdentityOAuthAdminException {
        OAuthAppDO[] oauthAppsOfUser;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            String tenantDomain = realmService.getTenantManager().getDomain(tenantId);
            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
            String tenantQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUserName, tenantDomain);
            boolean isUsernameCaseSensitive = isUsernameCaseSensitive(tenantQualifiedUsername);

            String sql = SQLQueries.OAuthAppDAOSQLQueries.GET_CONSUMER_APPS_OF_USER_WITH_PKCE;

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(USERNAME, LOWER_USERNAME);
            }
            try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {
                if (isUsernameCaseSensitive) {
                    prepStmt.setString(1, UserCoreUtil.removeDomainFromName(tenantAwareUserName));
                } else {
                    prepStmt.setString(1,
                            UserCoreUtil.removeDomainFromName(tenantAwareUserName).toLowerCase());
                }
                prepStmt.setString(2, IdentityUtil.extractDomainFromName(tenantAwareUserName));
                prepStmt.setInt(3, tenantId);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    List<OAuthAppDO> oauthApps = new ArrayList<>();
                    while (rSet.next()) {
                        if (rSet.getString(3) != null && rSet.getString(3).length() > 0) {
                            OAuthAppDO oauthApp = new OAuthAppDO();
                            String preprocessedClientId = persistenceProcessor.getPreprocessedClientId(rSet.getString
                                    (1));

                            oauthApp.setOauthConsumerKey(preprocessedClientId);
                            oauthApp.setOauthConsumerKey(persistenceProcessor.getPreprocessedClientId(rSet.getString
                                    (1)));
                            if (isHashDisabled) {
                                oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet
                                        .getString(2)));
                            }
                            oauthApp.setApplicationName(rSet.getString(3));
                            oauthApp.setOauthVersion(rSet.getString(4));
                            oauthApp.setCallbackUrl(rSet.getString(5));
                            oauthApp.setGrantTypes(rSet.getString(6));
                            oauthApp.setId(rSet.getInt(7));
                            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                            authenticatedUser.setUserName(rSet.getString(8));
                            authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(rSet.getInt(9)));
                            authenticatedUser.setUserStoreDomain(rSet.getString(10));
                            oauthApp.setPkceMandatory(!"0".equals(rSet.getString(11)));
                            oauthApp.setPkceSupportPlain(!"0".equals(rSet.getString(12)));
                            oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(13));
                            oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(14));
                            oauthApp.setRefreshTokenExpiryTime(rSet.getLong(15));
                            oauthApp.setIdTokenExpiryTime(rSet.getLong(16));
                            oauthApp.setUser(authenticatedUser);
                            String spTenantDomain = authenticatedUser.getTenantDomain();
                            handleSpOIDCProperties(connection, preprocessedClientId, spTenantDomain, oauthApp);
                            oauthApp.setScopeValidators(getScopeValidators(connection, oauthApp.getId()));
                            oauthApps.add(oauthApp);
                        }
                    }
                    oauthAppsOfUser = oauthApps.toArray(new OAuthAppDO[oauthApps.size()]);
                }
            }
        } catch (SQLException e) {
            throw handleError("Error occurred while retrieving OAuth consumer apps of user", e);
        } catch (UserStoreException e) {
            throw handleError("Error while retrieving Tenant Domain for tenant ID : " + tenantId, e);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while processing client id and client secret by " +
                    "TokenPersistenceProcessor", e);
        }
        return oauthAppsOfUser;
    }

    public OAuthAppDO getAppInformation(String consumerKey) throws
            InvalidOAuthClientException, IdentityOAuth2Exception {

        OAuthAppDO oauthApp = null;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_WITH_PKCE;

            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                String preprocessedClientId = persistenceProcessor.getProcessedClientId(consumerKey);
                prepStmt.setString(1, preprocessedClientId);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    /*
                      We need to determine whether the result set has more than 1 row. Meaning, we found an
                      application for
                      the given consumer key. There can be situations where a user passed a key which doesn't yet
                      have an
                      associated application. We need to barf with a meaningful error message for this case
                    */
                    boolean appExists = false;
                    while (rSet.next()) {
                        // There is at least one application associated with a given key
                        appExists = true;
                        if (rSet.getString(4) != null && rSet.getString(4).length() > 0) {
                            oauthApp = new OAuthAppDO();
                            oauthApp.setOauthConsumerKey(consumerKey);
                            if (isHashDisabled) {
                                oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet
                                        .getString(1)));
                            } else {
                                oauthApp.setOauthConsumerSecret(rSet.getString(1));
                            }
                            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                            authenticatedUser.setUserName(rSet.getString(2));
                            oauthApp.setApplicationName(rSet.getString(3));
                            oauthApp.setOauthVersion(rSet.getString(4));
                            oauthApp.setCallbackUrl(rSet.getString(5));
                            authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(rSet.getInt(6)));
                            authenticatedUser.setUserStoreDomain(rSet.getString(7));
                            oauthApp.setUser(authenticatedUser);
                            oauthApp.setGrantTypes(rSet.getString(8));
                            oauthApp.setId(rSet.getInt(9));
                            oauthApp.setPkceMandatory(!"0".equals(rSet.getString(10)));
                            oauthApp.setPkceSupportPlain(!"0".equals(rSet.getString(11)));
                            oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(12));
                            oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(13));
                            oauthApp.setRefreshTokenExpiryTime(rSet.getLong(14));
                            oauthApp.setIdTokenExpiryTime(rSet.getLong(15));
                            oauthApp.setState(rSet.getString(16));

                            String spTenantDomain = authenticatedUser.getTenantDomain();
                            handleSpOIDCProperties(connection, preprocessedClientId, spTenantDomain, oauthApp);
                            oauthApp.setScopeValidators(getScopeValidators(connection, oauthApp.getId()));
                        }
                    }

                    if (!appExists) {
                        handleRequestForANonExistingConsumerKey(consumerKey);
                    }
                    connection.commit();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the app information", e);
        }
        return oauthApp;
    }

    public OAuthAppDO getAppInformationByAppName(String appName) throws
            InvalidOAuthClientException, IdentityOAuth2Exception {
        OAuthAppDO oauthApp;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
            String sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_BY_APP_NAME_WITH_PKCE;

            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                prepStmt.setString(1, appName);
                prepStmt.setInt(2, tenantID);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    oauthApp = new OAuthAppDO();
                    oauthApp.setApplicationName(appName);
                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantID));
                    /*
                      We need to determine whether the result set has more than 1 row. Meaning, we found an
                      application for the given consumer key. There can be situations where a user passed a key which
                       doesn't yet have an associated application. We need to barf with a meaningful error message for
                        this case.
                     */
                    boolean appExists = false;
                    while (rSet.next()) {
                        // There is at least one application associated with a given key
                        appExists = true;
                        if (rSet.getString(4) != null && rSet.getString(4).length() > 0) {
                            if (isHashDisabled) {
                                oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet
                                        .getString(1)));
                            } else {
                                oauthApp.setOauthConsumerSecret(rSet.getString(1));
                            }
                            user.setUserName(rSet.getString(2));
                            user.setUserStoreDomain(rSet.getString(3));
                            oauthApp.setUser(user);

                            String preprocessedClientId = persistenceProcessor.getPreprocessedClientId(rSet.getString
                                    (4));
                            oauthApp.setOauthConsumerKey(preprocessedClientId);
                            oauthApp.setOauthVersion(rSet.getString(5));
                            oauthApp.setCallbackUrl(rSet.getString(6));
                            oauthApp.setGrantTypes(rSet.getString(7));
                            oauthApp.setId(rSet.getInt(8));
                            oauthApp.setPkceMandatory(!"0".equals(rSet.getString(9)));
                            oauthApp.setPkceSupportPlain(!"0".equals(rSet.getString(10)));
                            oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(11));
                            oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(12));
                            oauthApp.setRefreshTokenExpiryTime(rSet.getLong(13));
                            oauthApp.setIdTokenExpiryTime(rSet.getLong(14));

                            String spTenantDomain = user.getTenantDomain();
                            handleSpOIDCProperties(connection, preprocessedClientId, spTenantDomain, oauthApp);
                            oauthApp.setScopeValidators(getScopeValidators(connection, oauthApp.getId()));
                        }
                    }

                    if (!appExists) {
                        handleRequestForANonExistingApp(appName);
                    }
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the app information", e);
        }
        return oauthApp;
    }

    public void updateConsumerApplication(OAuthAppDO oauthAppDO) throws IdentityOAuthAdminException {
        boolean isUserValidForOwnerUpdate = validateUserForOwnerUpdate(oauthAppDO);
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sqlQuery = getSqlQuery(isUserValidForOwnerUpdate);
            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                prepStmt.setString(1, oauthAppDO.getApplicationName());
                prepStmt.setString(2, oauthAppDO.getCallbackUrl());
                prepStmt.setString(3, oauthAppDO.getGrantTypes());

                if (isUserValidForOwnerUpdate) {
                    setValuesToStatementWithPKCEAndOwnerUpdate(oauthAppDO, prepStmt);
                } else {
                    setValuesToStatementWithPKCENoOwnerUpdate(oauthAppDO, prepStmt);
                }
                int count = prepStmt.executeUpdate();
                updateScopeValidators(connection, oauthAppDO.getId(), oauthAppDO.getScopeValidators());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No. of records updated for updating consumer application. : " + count);
                }

                addOrUpdateOIDCSpProperty(oauthAppDO, connection);
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw handleError("Error when updating OAuth application", e1);
            }
        } catch (SQLException e) {
            throw handleError("Error when updating OAuth application", e);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while processing client id and client secret by " +
                    "TokenPersistenceProcessor", e);
        }
    }

    private boolean validateUserForOwnerUpdate(OAuthAppDO oAuthAppDO) throws IdentityOAuthAdminException {

        String userName = null;
        String domainName = null;
        if (oAuthAppDO.getAppOwner() != null) {
            userName = oAuthAppDO.getAppOwner().getUserName();
            if (StringUtils.isEmpty(userName) || CarbonConstants.REGISTRY_SYSTEM_USERNAME.equals(userName)) {
                return false;
            }
            domainName = oAuthAppDO.getAppOwner().getUserStoreDomain();
        }
       return isUserExists(userName, domainName);
    }

    private boolean isUserExists(String userName, String domainName) throws IdentityOAuthAdminException {

        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            Optional<User> user = OAuthUtil.getUser(tenantDomain, usernameWithDomain);
            return user.isPresent();
        } catch (IdentityApplicationManagementException e) {
            throw handleError("Error while checking user existence of user: " + usernameWithDomain, e);
        }
    }

    /**
     * Validate existence before oauth application update.
     *
     * @param serviceProvider Service Provider.
     * @return Whether app owner is valid.
     * @throws IdentityOAuthAdminException When error occurred while validating app owner.
     */
    private boolean validateUserForOwnerUpdate(ServiceProvider serviceProvider) throws IdentityOAuthAdminException {

        if (serviceProvider.getOwner() == null) {
            return false;
        }
        String userName = serviceProvider.getOwner().getUserName();
        if (StringUtils.isEmpty(userName) || CarbonConstants.REGISTRY_SYSTEM_USERNAME.equals(userName)) {
            return false;
        }
        String domainName = serviceProvider.getOwner().getUserStoreDomain();
        return isUserExists(userName, domainName);
    }

    private String getSqlQuery(boolean isUserValidForOwnerUpdate) {

        String sqlQuery;
        if (isUserValidForOwnerUpdate) {
            sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_PKCE_AND_OWNER_UPDATE;
        } else {
            sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_PKCE;
        }
        return sqlQuery;
    }

    private void setValuesToStatementWithPKCEAndOwnerUpdate(OAuthAppDO oauthAppDO, PreparedStatement prepStmt)
            throws SQLException, IdentityOAuth2Exception {

        prepStmt.setString(4, oauthAppDO.isPkceMandatory() ? "1" : "0");
        prepStmt.setString(5, oauthAppDO.isPkceSupportPlain() ? "1" : "0");
        prepStmt.setLong(6, oauthAppDO.getUserAccessTokenExpiryTime());
        prepStmt.setLong(7, oauthAppDO.getApplicationAccessTokenExpiryTime());
        prepStmt.setLong(8, oauthAppDO.getRefreshTokenExpiryTime());
        prepStmt.setLong(9, oauthAppDO.getIdTokenExpiryTime());
        prepStmt.setString(10, oauthAppDO.getAppOwner().getUserName());
        prepStmt.setString(11, oauthAppDO.getAppOwner().getUserStoreDomain());
        prepStmt.setString(12, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
    }

    private void setValuesToStatementWithPKCENoOwnerUpdate(OAuthAppDO oauthAppDO, PreparedStatement prepStmt)
            throws SQLException, IdentityOAuth2Exception {

        prepStmt.setString(4, oauthAppDO.isPkceMandatory() ? "1" : "0");
        prepStmt.setString(5, oauthAppDO.isPkceSupportPlain() ? "1" : "0");
        prepStmt.setLong(6, oauthAppDO.getUserAccessTokenExpiryTime());
        prepStmt.setLong(7, oauthAppDO.getApplicationAccessTokenExpiryTime());
        prepStmt.setLong(8, oauthAppDO.getRefreshTokenExpiryTime());
        prepStmt.setLong(9, oauthAppDO.getIdTokenExpiryTime());
        prepStmt.setString(10, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
    }

    private void addOrUpdateOIDCSpProperty(OAuthAppDO oauthAppDO,
                                           Connection connection) throws IdentityOAuth2Exception, SQLException {

        String preprocessedClientId = persistenceProcessor.getPreprocessedClientId(oauthAppDO.getOauthConsumerKey());
        String spTenantDomain = oauthAppDO.getUser().getTenantDomain();
        int spTenantId = IdentityTenantUtil.getTenantId(spTenantDomain);

        // Get the current OIDC SP properties.
        Map<String, List<String>> spOIDCProperties =
                getSpOIDCProperties(connection, preprocessedClientId, spTenantDomain);

        // Add new entry in IDN_OIDC_PROPERTY table for each new OIDC property.
        PreparedStatement prepStatementForPropertyAdd =
                connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_SP_OIDC_PROPERTY);

        PreparedStatement preparedStatementForPropertyUpdate =
                connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_SP_OIDC_PROPERTY);

        PreparedStatement prepStatementForPropertyDelete =
                connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.REMOVE_SP_OIDC_PROPERTY);

        if (isOAuthLegacyAudiencesEnabled()) {
            if (isOIDCAudienceEnabled()) {
                String[] audiences = oauthAppDO.getAudiences();
                List<String> oidcAudienceList = getOIDCAudiences(spTenantDomain, oauthAppDO.getOauthConsumerKey());
                updateAudiences(preprocessedClientId, spTenantId, audiences, prepStatementForPropertyAdd,
                        prepStatementForPropertyDelete, oidcAudienceList, OPENID_CONNECT_AUDIENCE);
            }
        } else {
            String[] idTokenAudiences = oauthAppDO.getIdTokenAudiences();
            List<String> idTokenAudienceList = getOIDCIdTokenAudiences(spTenantDomain,
                    oauthAppDO.getOauthConsumerKey());
            updateAudiences(preprocessedClientId, spTenantId, idTokenAudiences, prepStatementForPropertyAdd,
                    prepStatementForPropertyDelete, idTokenAudienceList, OPENID_CONNECT_ID_TOKEN_AUDIENCE);

            String[] accessTokenAudiences = oauthAppDO.getAccessTokenAudiences();
            List<String> accessTokenAudienceList = getOIDCAccessTokenAudiences(spTenantDomain,
                    oauthAppDO.getOauthConsumerKey());
            updateAudiences(preprocessedClientId, spTenantId, accessTokenAudiences, prepStatementForPropertyAdd,
                    prepStatementForPropertyDelete, accessTokenAudienceList, OPENID_CONNECT_ACCESS_TOKEN_AUDIENCE);

        }

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, REQUEST_OBJECT_SIGNED,
                String.valueOf(oauthAppDO.isRequestObjectSignatureValidationEnabled()),
                prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, ID_TOKEN_ENCRYPTED,
                String.valueOf(oauthAppDO.isIdTokenEncryptionEnabled()),
                prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, ID_TOKEN_ENCRYPTION_ALGORITHM,
                String.valueOf(oauthAppDO.getIdTokenEncryptionAlgorithm()),
                prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, ID_TOKEN_ENCRYPTION_METHOD,
                String.valueOf(oauthAppDO.getIdTokenEncryptionMethod()),
                prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, BACK_CHANNEL_LOGOUT_URL,
                oauthAppDO.getBackChannelLogoutUrl(), prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, FRONT_CHANNEL_LOGOUT_URL,
                oauthAppDO.getFrontchannelLogoutUrl(), prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, TOKEN_TYPE,
                oauthAppDO.getTokenType(), prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, BYPASS_CLIENT_CREDENTIALS,
                String.valueOf(oauthAppDO.isBypassClientCredentials()), prepStatementForPropertyAdd,
                preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, RENEW_REFRESH_TOKEN,
                oauthAppDO.getRenewRefreshTokenEnabled(), prepStatementForPropertyAdd,
                preparedStatementForPropertyUpdate);

        if (TOKEN_BINDING_TYPE_NONE.equalsIgnoreCase(oauthAppDO.getTokenBindingType())) {
            oauthAppDO.setTokenBindingType(null);
        }
        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties, TOKEN_BINDING_TYPE,
                oauthAppDO.getTokenBindingType(), prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        // Token binding is required to enable following features.
        if (oauthAppDO.getTokenBindingType() == null) {
            oauthAppDO.setTokenRevocationWithIDPSessionTerminationEnabled(false);
            oauthAppDO.setTokenBindingValidationEnabled(false);
        }

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties,
                TOKEN_REVOCATION_WITH_IDP_SESSION_TERMINATION,
                String.valueOf(oauthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()),
                prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        addOrUpdateOIDCSpProperty(preprocessedClientId, spTenantId, spOIDCProperties,
                TOKEN_BINDING_VALIDATION, String.valueOf(oauthAppDO.isTokenBindingValidationEnabled()),
                prepStatementForPropertyAdd, preparedStatementForPropertyUpdate);

        // Execute batched add/update/delete.
        prepStatementForPropertyAdd.executeBatch();
        preparedStatementForPropertyUpdate.executeBatch();
        prepStatementForPropertyDelete.executeBatch();
    }

    private void updateAudiences(String preprocessedClientId, int spTenantId, String[] audiences,
                                          PreparedStatement prepStatementForPropertyAdd,
                                          PreparedStatement prepStatementForPropertyDelete,
                                          List<String> oidcAudienceList, String propertyKey)
            throws SQLException {

        HashSet<String> newAudiences = audiences == null ? new HashSet<>() : new HashSet<>(Arrays.asList
                (audiences));
        Set<String> currentAudiences = oidcAudienceList == null ? new HashSet<>() : new HashSet<>(oidcAudienceList);
        HashSet<String> newAudienceClone = (HashSet<String>) newAudiences.clone();
        //removing all duplicate audiences in the new audience list
        newAudiences.removeAll(currentAudiences);
        //obtaining the audience values deleted in the list by user
        currentAudiences.removeAll(newAudienceClone);

        for (String deletedAudience : currentAudiences) {
            addToBatchForOIDCPropertyDelete(preprocessedClientId, spTenantId, prepStatementForPropertyDelete,
                    propertyKey, deletedAudience);
        }

        for (String addedAudience : newAudiences) {
            addToBatchForOIDCPropertyAdd(preprocessedClientId, spTenantId, prepStatementForPropertyAdd,
                    propertyKey, addedAudience);
        }

    }

    private void addOrUpdateOIDCSpProperty(String preprocessedClientId,
                                           int spTenantId,
                                           Map<String, List<String>> spOIDCProperties,
                                           String propertyKey, String propertyValue,
                                           PreparedStatement preparedStatementForPropertyAdd,
                                           PreparedStatement preparedStatementForPropertyUpdate) throws SQLException {

        if (propertyAlreadyExists(spOIDCProperties, propertyKey)) {
            addToBatchForOIDCPropertyUpdate(preprocessedClientId, spTenantId, preparedStatementForPropertyUpdate,
                    propertyKey, propertyValue);
        } else {
            addToBatchForOIDCPropertyAdd(preprocessedClientId, spTenantId, preparedStatementForPropertyAdd,
                    propertyKey, propertyValue);
        }

    }

    private void addToBatchForOIDCPropertyAdd(String consumerKey,
                                              int tenantId,
                                              PreparedStatement preparedStatement,
                                              String propertyKey,
                                              String propertyValue) throws SQLException {
        preparedStatement.setInt(1, tenantId);
        preparedStatement.setString(2, consumerKey);
        preparedStatement.setString(3, propertyKey);
        preparedStatement.setString(4, propertyValue);
        preparedStatement.addBatch();
    }

    private void addToBatchForOIDCPropertyDelete(String consumerKey,
                                                 int tenantId,
                                                 PreparedStatement preparedStatement,
                                                 String propertyKey,
                                                 String propertyValue) throws SQLException {
        preparedStatement.setString(1, consumerKey);
        preparedStatement.setInt(2, tenantId);
        preparedStatement.setString(3, propertyKey);
        preparedStatement.setString(4, propertyValue);
        preparedStatement.addBatch();
    }

    private void addToBatchForOIDCPropertyUpdate(String consumerKey,
                                                 int tenantId,
                                                 PreparedStatement preparedStatement,
                                                 String propertyKey,
                                                 String propertyValue) throws SQLException {
        preparedStatement.setString(1, propertyValue);
        preparedStatement.setString(2, consumerKey);
        preparedStatement.setInt(3, tenantId);
        preparedStatement.setString(4, propertyKey);
        preparedStatement.addBatch();
    }

    private boolean propertyAlreadyExists(Map<String, List<String>> spOIDCProperties, String propertyKey) {
        return spOIDCProperties.containsKey(propertyKey);
    }

    public void removeConsumerApplication(String consumerKey) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement prepStmt = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.REMOVE_APPLICATION)) {
                prepStmt.setString(1, consumerKey);
                prepStmt.execute();
                if (isOAuthLegacyAudiencesEnabled()) {
                    if (isOIDCAudienceEnabled()) {
                        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                        removeOauthOIDCPropertyTable(connection, tenantDomain, consumerKey);
                    }
                } else {
                    String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                    removeOauthOIDCPropertyTable(connection, tenantDomain, consumerKey);
                }
                IdentityDatabaseUtil.commitTransaction(connection);
            }
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries
                    .REMOVE_APPLICATION, e);
        }
    }

    /**
     * Delete all consumer applications of a given tenant.
     *
     * @param tenantId Id of the tenant
     * @throws IdentityOAuthAdminException
     */
    public void removeConsumerApplicationsByTenantId(int tenantId) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(true)) {

            // Delete SP Apps Associations
            removeSPAssociations(tenantId, connection);

            // Delete Consumer Applications
            try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries
                     .REMOVE_APPLICATIONS_BY_TENANT_ID)) {
                prepStmt.setInt(1, tenantId);
                prepStmt.execute();
            }

            // Delete all OIDC Properties
            if (isOIDCAudienceEnabled()) {
                removeOAuthOIDCPropertiesByTenantId(connection, tenantId);
            }

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            throw handleError("Error when deleting consumer apps of the tenant: " + tenantId, e);
        }
    }

    /**
     * Update the OAuth service provider name.
     *
     * @param appName     Service provider name.
     * @param consumerKey Consumer key.
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     */
    public void updateOAuthConsumerApp(String appName, String consumerKey)
            throws IdentityApplicationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement
                         statement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_OAUTH_INFO)) {
                statement.setString(1, appName);
                statement.setString(2, consumerKey);
                statement.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e1);
            }
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        }
    }

    /**
     * Update app name and owner in oauth client if the app owner is valid, Otherwise update only the app name.
     *
     * @param serviceProvider Service provider.
     * @param consumerKey     Consumer key of the Oauth app.
     * @throws IdentityApplicationManagementException Error while updating Oauth app details.
     * @throws IdentityOAuthAdminException            Error occurred while validating app owner.
     */
    public void updateOAuthConsumerApp(ServiceProvider serviceProvider, String consumerKey)
            throws IdentityApplicationManagementException, IdentityOAuthAdminException {

        if (validateUserForOwnerUpdate(serviceProvider)) {
            try (Connection connection = IdentityDatabaseUtil.getDBConnection(true);
                 PreparedStatement statement = connection.prepareStatement(
                         SQLQueries.OAuthAppDAOSQLQueries.UPDATE_OAUTH_CLIENT_WITH_OWNER)) {
                    statement.setString(1, serviceProvider.getApplicationName());
                    statement.setString(2, serviceProvider.getOwner().getUserName());
                    statement.setString(3, serviceProvider.getOwner().getUserStoreDomain());
                    statement.setString(4, consumerKey);
                    statement.execute();
                    IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e) {
                throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
            }
        } else {
            updateOAuthConsumerApp(serviceProvider.getApplicationName(), consumerKey);
        }
    }

    public String getConsumerAppState(String consumerKey) throws IdentityOAuthAdminException {
        String consumerAppState = null;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false); PreparedStatement
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APPLICATION_STATE)) {

            prepStmt.setString(1, consumerKey);
            try (ResultSet rSet = prepStmt.executeQuery()) {
                if (rSet.next()) {
                    consumerAppState = rSet.getString(APP_STATE);
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No App found for the consumerKey: " + consumerKey);
                    }
                }
            }
        } catch (SQLException e) {
            throw handleError("Error while executing the SQL prepStmt.", e);
        }
        return consumerAppState;
    }

    public void updateConsumerAppState(String consumerKey, String state) throws
            IdentityApplicationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement statement = connection
                    .prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_APPLICATION_STATE)) {
                statement.setString(1, state);
                statement.setString(2, consumerKey);
                statement.execute();
                IdentityDatabaseUtil.commitTransaction(connection);
            } catch (SQLException e1) {
                IdentityDatabaseUtil.rollbackTransaction(connection);
                throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e1);
            }
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        }
    }

    public boolean isDuplicateApplication(String username, int tenantId, String userDomain, OAuthAppDO
            consumerAppDTO)
            throws IdentityOAuthAdminException {

        boolean isDuplicateApp = false;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(username, tenantId);

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {
            String sql = SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_APPLICATION;
            if (!isUsernameCaseSensitive) {
                sql = sql.replace(USERNAME, LOWER_USERNAME);
            }
            try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {
                if (isUsernameCaseSensitive) {
                    prepStmt.setString(1, username);
                } else {
                    prepStmt.setString(1, username.toLowerCase());
                }
                prepStmt.setInt(2, tenantId);
                prepStmt.setString(3, userDomain);
                prepStmt.setString(4, consumerAppDTO.getApplicationName());

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    if (rSet.next()) {
                        isDuplicateApp = true;
                    }
                }
            }
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries
                    .CHECK_EXISTING_APPLICATION, e);
        }
        return isDuplicateApp;
    }

    public boolean isDuplicateConsumer(String consumerKey) throws IdentityOAuthAdminException {

        boolean isDuplicateConsumer = false;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false); PreparedStatement
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_CONSUMER)) {
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));

            try (ResultSet rSet = prepStmt.executeQuery()) {
                if (rSet.next()) {
                    isDuplicateConsumer = true;
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while processing the client id by TokenPersistenceProcessor", null);
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL: " + SQLQueries.OAuthAppDAOSQLQueries
                    .CHECK_EXISTING_CONSUMER, e);
        }
        return isDuplicateConsumer;
    }

    private boolean isUsernameCaseSensitive(String tenantQualifiedUsername) {

        return IdentityUtil.isUserStoreInUsernameCaseSensitive(tenantQualifiedUsername);
    }

    /**
     * Retrieves OIDC audience values configured for an oauth consumer app.
     *
     * @param tenantDomain application tenant domain
     * @param consumerKey  client ID
     * @return idTokenAudiences audience values for Id Token
     * @throws IdentityOAuth2Exception
     */
    /**
     * @deprecated use {@link #getOIDCIdTokenAudiences(String, String )} |
     * {@link #getOIDCAccessokenAudiences(String, String )} instead.
     */
    @Deprecated
    public List<String> getOIDCAudiences(String tenantDomain, String consumerKey) throws IdentityOAuth2Exception {

        if (isOAuthLegacyAudiencesEnabled()) {
            List<String> audiences = getAudiencesFromDB(tenantDomain, consumerKey, OPENID_CONNECT_AUDIENCE);
            return audiences;
        } else {
            return this.getOIDCIdTokenAudiences(tenantDomain, consumerKey);
        }
    }

    /**
     * Retrieves OIDC ID Token audience values configured for an oauth consumer app.
     *
     * @param tenantDomain application tenant domain
     * @param consumerKey  client ID
     * @return idTokenAudiences audience values for Id Token
     * @throws IdentityOAuth2Exception
     */
    public List<String> getOIDCIdTokenAudiences(String tenantDomain, String consumerKey)
            throws IdentityOAuth2Exception {

        List<String> idTokenAudiences = getAudiencesFromDB(tenantDomain, consumerKey, OPENID_CONNECT_ID_TOKEN_AUDIENCE);
        return idTokenAudiences;
    }


    /**
     * Retrieves OIDC Access Token audience values configured for an oauth consumer app.
     *
     * @param tenantDomain application tenant domain
     * @param consumerKey  client ID
     * @return accessTokenAudiences audience values for Access Token
     * @throws IdentityOAuth2Exception
     */
    public List<String> getOIDCAccessTokenAudiences(String tenantDomain, String consumerKey)
            throws IdentityOAuth2Exception {

        List<String> accessTokenAudiences = getAudiencesFromDB(tenantDomain, consumerKey,
                OPENID_CONNECT_ACCESS_TOKEN_AUDIENCE);
        return accessTokenAudiences;
    }

    private List<String> getAudiencesFromDB(String tenantDomain, String consumerKey,
                                            String propertyKey)

            throws IdentityOAuth2Exception {

        List<String> audiences = new ArrayList<>();
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        PreparedStatement prepStmt = null;
        ResultSet rSetAudiences = null;
        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_SP_OIDC_PROPERTY);
            prepStmt.setString(1, consumerKey);
            prepStmt.setInt(2, IdentityTenantUtil.getTenantId(tenantDomain));
            prepStmt.setString(3, propertyKey);
            rSetAudiences = prepStmt.executeQuery();
            while (rSetAudiences.next()) {
                String audience = rSetAudiences.getString(1);
                if (audience != null) {
                    audiences.add(rSetAudiences.getString(1));
                }
            }
        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving OIDC Access Token audiences for client ID: " +
                    consumerKey + " and tenant domain: " + tenantDomain;
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rSetAudiences, prepStmt);
        }
        return audiences;
    }
    /**
     * Remove Oauth consumer app related properties.
     *
     * @param tenantDomain application tenant domain
     * @param consumerKey  client ID
     * @throws IdentityOAuthAdminException
     */
    public void removeOIDCProperties(String tenantDomain, String consumerKey) throws IdentityOAuthAdminException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        try {
            removeOauthOIDCPropertyTable(connection, tenantDomain, consumerKey);
            IdentityDatabaseUtil.commitTransaction(connection);
        } catch (SQLException e) {
            String errorMsg = "Error removing OIDC properties for client ID: " + consumerKey + " and tenant domain: "
                    + tenantDomain;
            IdentityDatabaseUtil.rollbackTransaction(connection);
            throw new IdentityOAuthAdminException(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, null);
        }
    }

    private void removeOauthOIDCPropertyTable(Connection connection, String tenantDomain, String consumerKey) throws
            SQLException {

        try (PreparedStatement prepStmt =
                     connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.REMOVE_ALL_SP_OIDC_PROPERTIES)) {
            prepStmt.setString(1, consumerKey);
            prepStmt.setInt(2, IdentityTenantUtil.getTenantId(tenantDomain));
            prepStmt.execute();
        }
    }

    /**
     * Delete all OAuth OIDC Properties of a given tenant.
     *
     * @param connection DB connection
     * @param tenantId Id of the tenant
     * @throws SQLException
     */
    private void removeOAuthOIDCPropertiesByTenantId(Connection connection, int tenantId) throws SQLException {

        try (PreparedStatement prepStmt = connection.prepareStatement(
                SQLQueries.OAuthAppDAOSQLQueries.REMOVE_ALL_SP_OIDC_PROPERTIES_BY_TENANT_ID)) {
            prepStmt.setInt(1, tenantId);
            prepStmt.execute();
        }
    }

    /**
     * Remove all SP associations of all OAuth apps of a given tenant.
     *
     * @param tenantId Id of the tenant
     * @param connection DB connection
     * @throws SQLException
     */
    private void removeSPAssociations(int tenantId, Connection connection) throws SQLException {

        for (String consumerKey : getOAuthConsumerKeysByTenantId(tenantId, connection)) {
            try (PreparedStatement prepStmt = connection.prepareStatement(
                    SQLQueries.OAuthAppDAOSQLQueries.REMOVE_SP_ASSOCIATIONS_BY_CONSUMER_ID)) {
                prepStmt.setString(1, consumerKey);
                prepStmt.execute();
            }
        }
    }

    /**
     * Get a list of all Consumer Keys of a given tenant.
     *
     * @param tenantId Id of the tenant
     * @param connection DB connection
     * @return
     * @throws SQLException
     */
    private List<String> getOAuthConsumerKeysByTenantId(int tenantId, Connection connection) throws SQLException {

        List<String> oauthConsumerKeys = new ArrayList<>();
        try (PreparedStatement prepStmt = connection.prepareStatement(
                SQLQueries.OAuthAppDAOSQLQueries.GET_CONSUMER_KEYS_BY_TENANT_ID)) {
            prepStmt.setInt(1, tenantId);

            try (ResultSet rSet = prepStmt.executeQuery()) {
                while (rSet.next()) {
                    oauthConsumerKeys.add(rSet.getString(1));
                }
            }
        }
        return oauthConsumerKeys;
    }

    /**
     * Add scope validators for consumerApp using connection.
     *
     * @param connection      Same db connection used in OAuth creation.
     * @param appId           Id of consumerApp.
     * @param scopeValidators List of scope validators.
     * @throws SQLException Sql error.
     */
    private void addScopeValidators(Connection connection, int appId, String[] scopeValidators) throws SQLException {

        if (scopeValidators != null && scopeValidators.length > 0) {
            LOG.debug(String.format("Adding %d Scope validators registered for OAuth appId %d",
                    scopeValidators.length, appId));
            try (PreparedStatement stmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries
                    .ADD_APP_SCOPE_VALIDATOR)) {
                for (String scopeValidator : scopeValidators) {
                    stmt.setInt(1, appId);
                    stmt.setString(2, scopeValidator);
                    stmt.addBatch();
                }
                stmt.executeBatch();
            }
        }
    }

    /**
     * Retrieve all scope validators for specific appId.
     *
     * @param connection Same db connection used in retrieving OAuth App.
     * @param id         AppId of the OAuth app.
     * @return List of scope validator names.
     * @throws SQLException Sql error.
     */
    private String[] getScopeValidators(Connection connection, int id) throws SQLException {

        List<String> scopeValidators = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries
                .GET_APP_SCOPE_VALIDATORS)) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    scopeValidators.add(rs.getString(1));
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Retrieving %d Scope validators registered for OAuth appId %d",
                    scopeValidators.size(), id));
        }
        return scopeValidators.toArray(new String[0]);
    }

    /**
     * Update the scope validator of OAuth app by remove all the registered scope validators and then add as new entry.
     *
     * @param connection      Same db connection used in OAuth update.
     * @param appId           Id of consumerApp.
     * @param scopeValidators List of scope validators.
     * @throws SQLException Sql error.
     */
    private void updateScopeValidators(Connection connection, int appId, String[] scopeValidators)
            throws SQLException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Removing  Scope validators registered for OAuth appId %d", appId));
        }
        try (PreparedStatement stmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries
                .REMOVE_APP_SCOPE_VALIDATORS)) {
            stmt.setInt(1, appId);
            stmt.execute();
        }
        addScopeValidators(connection, appId, scopeValidators);
    }

    /**
     * Get the application id using the client id.
     *
     * @param connection Same db connection used in OAuth creation.
     * @param clientId   Client id of the created app.
     * @return Application id of the client id.
     * @throws SQLException                Sql exception.
     * @throws InvalidOAuthClientException Invalid OAuth Client Exception.
     * @throws IdentityOAuth2Exception     Identity OAuth2 Exception.
     */
    private int getAppIdByClientId(Connection connection, String clientId)
            throws SQLException, InvalidOAuthClientException, IdentityOAuth2Exception {

        int appId = 0;
        try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries
                .GET_APP_ID_BY_CONSUMER_KEY)) {
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(clientId));
            try (ResultSet rSet = prepStmt.executeQuery()) {
                boolean rSetHasRows = false;
                while (rSet.next()) {
                    // There is at least one application associated with a given key.
                    rSetHasRows = true;
                    appId = rSet.getInt(1);
                }
                if (!rSetHasRows) {
                    String message = "Cannot find an application associated with the given consumer key : " + clientId;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(message);
                    }
                    throw new InvalidOAuthClientException(message);
                }
            }
        }
        return appId;
    }

    private void addServiceProviderOIDCProperties(Connection connection,
                                                  OAuthAppDO consumerAppDO,
                                                  String processedClientId,
                                                  int spTenantId) throws SQLException {

        try (PreparedStatement prepStmtAddOIDCProperty =
                     connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_SP_OIDC_PROPERTY)) {

            if (isOAuthLegacyAudiencesEnabled()) {
                if (isOIDCAudienceEnabled() && consumerAppDO.getAudiences() != null) {
                    String[] audiences = consumerAppDO.getAudiences();
                    for (String audience : audiences) {
                        addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                                OPENID_CONNECT_AUDIENCE, audience);
                    }
                }
            } else {
                if (consumerAppDO.getIdTokenAudiences() != null) {
                    String[] idTokenAudiences = consumerAppDO.getIdTokenAudiences();
                    for (String idTokenAudience : idTokenAudiences) {
                        addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                                OPENID_CONNECT_ID_TOKEN_AUDIENCE, idTokenAudience);
                    }
                }

                if (consumerAppDO.getAccessTokenAudiences() != null) {
                    String[] accessTokenAudiences = consumerAppDO.getAccessTokenAudiences();
                    for (String accessTokenAudience : accessTokenAudiences) {
                        addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                                OPENID_CONNECT_ACCESS_TOKEN_AUDIENCE, accessTokenAudience);
                    }
                }
            }

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    REQUEST_OBJECT_SIGNED, String.valueOf(consumerAppDO.isRequestObjectSignatureValidationEnabled()));

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    ID_TOKEN_ENCRYPTED, String.valueOf(consumerAppDO.isIdTokenEncryptionEnabled()));

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    ID_TOKEN_ENCRYPTION_ALGORITHM, String.valueOf(consumerAppDO.getIdTokenEncryptionAlgorithm()));

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    ID_TOKEN_ENCRYPTION_METHOD, String.valueOf(consumerAppDO.getIdTokenEncryptionMethod()));

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    BACK_CHANNEL_LOGOUT_URL, consumerAppDO.getBackChannelLogoutUrl());

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    FRONT_CHANNEL_LOGOUT_URL, consumerAppDO.getFrontchannelLogoutUrl());

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    TOKEN_TYPE, consumerAppDO.getTokenType());

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    BYPASS_CLIENT_CREDENTIALS, String.valueOf(consumerAppDO.isBypassClientCredentials()));

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    RENEW_REFRESH_TOKEN, consumerAppDO.getRenewRefreshTokenEnabled());

            if (TOKEN_BINDING_TYPE_NONE.equalsIgnoreCase(consumerAppDO.getTokenBindingType())) {
                consumerAppDO.setTokenBindingType(null);
            }
            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty, TOKEN_BINDING_TYPE,
                    consumerAppDO.getTokenBindingType());

            // Token binding is required to enable following features.
            if (consumerAppDO.getTokenBindingType() == null) {
                consumerAppDO.setTokenRevocationWithIDPSessionTerminationEnabled(false);
                consumerAppDO.setTokenBindingValidationEnabled(false);
            }

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    TOKEN_REVOCATION_WITH_IDP_SESSION_TERMINATION,
                    String.valueOf(consumerAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()));

            addToBatchForOIDCPropertyAdd(processedClientId, spTenantId, prepStmtAddOIDCProperty,
                    TOKEN_BINDING_VALIDATION,
                    String.valueOf(consumerAppDO.isTokenBindingValidationEnabled()));

            prepStmtAddOIDCProperty.executeBatch();
        }
    }

    private void handleSpOIDCProperties(Connection connection,
                                        String preprocessedClientId,
                                        String spTenantDomain,
                                        OAuthAppDO oauthApp) throws IdentityOAuth2Exception {

        Map<String, List<String>> spOIDCProperties =
                getSpOIDCProperties(connection, preprocessedClientId, spTenantDomain);

        // Set OIDC properties to IDN_OIDC_PROPERTY table.
        setSpOIDCProperties(spOIDCProperties, oauthApp);
    }

    private Map<String, List<String>> getSpOIDCProperties(Connection connection,
                                                          String consumerKey,
                                                          String spTenantDomain) throws IdentityOAuth2Exception {
        Map<String, List<String>> spOIDCProperties = new HashMap<>();
        PreparedStatement prepStatement = null;
        ResultSet spOIDCPropertyResultSet = null;
        try {
            prepStatement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_ALL_SP_OIDC_PROPERTIES);
            prepStatement.setString(1, consumerKey);
            prepStatement.setInt(2, IdentityTenantUtil.getTenantId(spTenantDomain));

            spOIDCPropertyResultSet = prepStatement.executeQuery();
            while (spOIDCPropertyResultSet.next()) {
                String propertyKey = spOIDCPropertyResultSet.getString(1);
                String propertyValue = spOIDCPropertyResultSet.getString(2);
                spOIDCProperties.computeIfAbsent(propertyKey, k -> new ArrayList<>()).add(propertyValue);
            }

        } catch (SQLException e) {
            String errorMsg = "Error occurred while retrieving OIDC properties for client ID: " + consumerKey +
                    " and tenant domain: " + spTenantDomain;
            throw new IdentityOAuth2Exception(errorMsg, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(null, spOIDCPropertyResultSet, prepStatement);
        }
        return spOIDCProperties;
    }

    private void setSpOIDCProperties(Map<String, List<String>> spOIDCProperties, OAuthAppDO oauthApp) {

        // Handle OIDC audience values
        if (isOAuthLegacyAudiencesEnabled()) {
            if (isOIDCAudienceEnabled() &&
                    CollectionUtils.isNotEmpty(spOIDCProperties.get(OPENID_CONNECT_AUDIENCE))) {
                List<String> oidcAudience = new ArrayList<>(spOIDCProperties.get(OPENID_CONNECT_AUDIENCE));
                oauthApp.setAudiences(oidcAudience.toArray(new String[oidcAudience.size()]));
            }
        } else {
            if (CollectionUtils.isNotEmpty(spOIDCProperties.get(OPENID_CONNECT_ID_TOKEN_AUDIENCE))) {
                List<String> oidcIdTokenAudience = new ArrayList<>(spOIDCProperties.get(
                        OPENID_CONNECT_ID_TOKEN_AUDIENCE));
                oauthApp.setIdTokenAudiences(oidcIdTokenAudience.toArray(new String[0]));
            }

            if (CollectionUtils.isNotEmpty(spOIDCProperties.get(OPENID_CONNECT_ACCESS_TOKEN_AUDIENCE))) {
                List<String> oidcAccessTokenAudience =
                        new ArrayList<>(spOIDCProperties.get(OPENID_CONNECT_ACCESS_TOKEN_AUDIENCE));
                oauthApp.setAccessTokenAudiences(oidcAccessTokenAudience
                        .toArray(new String[oidcAccessTokenAudience.size()]));
            }
        }

        // Handle other SP OIDC properties
        boolean isRequestObjectSigned = Boolean.parseBoolean(
                getFirstPropertyValue(spOIDCProperties, REQUEST_OBJECT_SIGNED));
        oauthApp.setRequestObjectSignatureValidationEnabled(isRequestObjectSigned);

        boolean isIdTokenEncrypted = Boolean.parseBoolean(
                getFirstPropertyValue(spOIDCProperties, ID_TOKEN_ENCRYPTED));
        oauthApp.setIdTokenEncryptionEnabled(isIdTokenEncrypted);

        String idTokenEncryptionAlgorithm = getFirstPropertyValue(spOIDCProperties, ID_TOKEN_ENCRYPTION_ALGORITHM);
        oauthApp.setIdTokenEncryptionAlgorithm(idTokenEncryptionAlgorithm);

        String idTokenEncryptionMethod = getFirstPropertyValue(spOIDCProperties, ID_TOKEN_ENCRYPTION_METHOD);
        oauthApp.setIdTokenEncryptionMethod(idTokenEncryptionMethod);

        String backChannelLogoutUrl = getFirstPropertyValue(spOIDCProperties, BACK_CHANNEL_LOGOUT_URL);
        oauthApp.setBackChannelLogoutUrl(backChannelLogoutUrl);

        String frontchannelLogoutUrl = getFirstPropertyValue(spOIDCProperties, FRONT_CHANNEL_LOGOUT_URL);
        oauthApp.setFrontchannelLogoutUrl(frontchannelLogoutUrl);

        String tokenType = getFirstPropertyValue(spOIDCProperties, TOKEN_TYPE);
        oauthApp.setTokenType(tokenType);

        boolean bypassClientCreds = Boolean.parseBoolean(
                getFirstPropertyValue(spOIDCProperties, BYPASS_CLIENT_CREDENTIALS));
        oauthApp.setBypassClientCredentials(bypassClientCreds);

        String tokenBindingType = getFirstPropertyValue(spOIDCProperties, TOKEN_BINDING_TYPE);
        if (TOKEN_BINDING_TYPE_NONE.equalsIgnoreCase(tokenBindingType)) {
            tokenBindingType = null;
        }
        oauthApp.setTokenBindingType(tokenBindingType);

        if (tokenBindingType == null) {
            oauthApp.setTokenRevocationWithIDPSessionTerminationEnabled(false);
            oauthApp.setTokenBindingValidationEnabled(false);
        } else {
            boolean isTokenRevocationEnabled = Boolean.parseBoolean(
                    getFirstPropertyValue(spOIDCProperties, TOKEN_REVOCATION_WITH_IDP_SESSION_TERMINATION));
            oauthApp.setTokenRevocationWithIDPSessionTerminationEnabled(isTokenRevocationEnabled);

            boolean isTokenBindingValidationEnabled = Boolean
                    .parseBoolean(getFirstPropertyValue(spOIDCProperties, TOKEN_BINDING_VALIDATION));
            oauthApp.setTokenBindingValidationEnabled(isTokenBindingValidationEnabled);
        }

        String renewRefreshToken = getFirstPropertyValue(spOIDCProperties, RENEW_REFRESH_TOKEN);
        oauthApp.setRenewRefreshTokenEnabled(renewRefreshToken);

    }

    private String getFirstPropertyValue(Map<String, List<String>> propertyMap, String key) {

        return CollectionUtils.isNotEmpty(propertyMap.get(key)) ? propertyMap.get(key).get(0) : null;
    }

    private boolean isOAuthLegacyAudiencesEnabled() {

        return OAuth2ServiceComponentHolder.isLegacyAudienceEnabled();
    }

    private boolean isOIDCAudienceEnabled() {
        return OAuth2ServiceComponentHolder.isAudienceEnabled();
    }

    private void handleRequestForANonExistingConsumerKey(String consumerKey) throws InvalidOAuthClientException {

        String message = "application.not.found";
        if (LOG.isDebugEnabled()) {
            LOG.debug("Cannot find an application associated with the given consumer key: " + consumerKey);
        }
        throw new InvalidOAuthClientException(message);
    }

    private void handleRequestForANonExistingApp(String appName) throws InvalidOAuthClientException {

        String message = "Cannot find an application associated with the given appName : " + appName;
        if (LOG.isDebugEnabled()) {
            LOG.debug(message);
        }
        throw new InvalidOAuthClientException(message);
    }
}
