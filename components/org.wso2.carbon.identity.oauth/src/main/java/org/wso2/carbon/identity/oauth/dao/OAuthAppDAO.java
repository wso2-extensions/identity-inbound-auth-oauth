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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.oauth.OAuthUtil.handleError;

/**
 * JDBC Based data access layer for OAuth Consumer Applications.
 */
public class OAuthAppDAO {

    public static final Log log = LogFactory.getLog(OAuthAppDAO.class);
    private static final String APP_STATE = "APP_STATE";
    private static final String USERNAME = "USERNAME";
    private static final String LOWER_USERNAME = "LOWER(USERNAME)";
    private TokenPersistenceProcessor persistenceProcessor;

    public OAuthAppDAO() {

        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextPersistenceProcessor");
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }

    }

    public void addOAuthApplication(OAuthAppDO consumerAppDO) throws IdentityOAuthAdminException {
        if (!isDuplicateApplication(consumerAppDO.getUser().getUserName(), IdentityTenantUtil.getTenantId(consumerAppDO
                .getUser().getTenantDomain()), consumerAppDO.getUser().getUserStoreDomain(), consumerAppDO)) {

            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
                if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                    try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP_WITH_PKCE)) {
                        prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerAppDO.getOauthConsumerKey()));
                        prepStmt.setString(2, persistenceProcessor.getProcessedClientSecret(consumerAppDO.getOauthConsumerSecret()));
                        prepStmt.setString(3, consumerAppDO.getUser().getUserName());
                        prepStmt.setInt(4, IdentityTenantUtil.getTenantId(consumerAppDO.getUser().getTenantDomain()));
                        prepStmt.setString(5, consumerAppDO.getUser().getUserStoreDomain());
                        prepStmt.setString(6, consumerAppDO.getApplicationName());
                        prepStmt.setString(7, consumerAppDO.getOauthVersion());
                        prepStmt.setString(8, consumerAppDO.getCallbackUrl());
                        prepStmt.setString(9, consumerAppDO.getGrantTypes());
                        prepStmt.setString(10, consumerAppDO.isPkceMandatory() ? "1" : "0");
                        prepStmt.setString(11, consumerAppDO.isPkceSupportPlain() ? "1" : "0");
                        prepStmt.setLong(12, consumerAppDO.getUserAccessTokenExpiryTime());
                        prepStmt.setLong(13, consumerAppDO.getApplicationAccessTokenExpiryTime());
                        prepStmt.setLong(14, consumerAppDO.getRefreshTokenExpiryTime());
                        prepStmt.setString(15, consumerAppDO.isTbMandatory() ? "1" : "0");
                        prepStmt.execute();
                        connection.commit();
                    }
                }else {
                    try (PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP)) {
                        prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerAppDO.getOauthConsumerKey()));
                        prepStmt.setString(2, persistenceProcessor.getProcessedClientSecret(consumerAppDO.getOauthConsumerSecret()));
                        prepStmt.setString(3, consumerAppDO.getUser().getUserName());
                        prepStmt.setInt(4, IdentityTenantUtil.getTenantId(consumerAppDO.getUser().getTenantDomain()));
                        prepStmt.setString(5, consumerAppDO.getUser().getUserStoreDomain());
                        prepStmt.setString(6, consumerAppDO.getApplicationName());
                        prepStmt.setString(7, consumerAppDO.getOauthVersion());
                        prepStmt.setString(8, consumerAppDO.getCallbackUrl());
                        prepStmt.setString(9, consumerAppDO.getGrantTypes());
                        prepStmt.setLong(10, consumerAppDO.getUserAccessTokenExpiryTime());
                        prepStmt.setLong(11, consumerAppDO.getApplicationAccessTokenExpiryTime());
                        prepStmt.setLong(12, consumerAppDO.getRefreshTokenExpiryTime());
                        prepStmt.setString(13, consumerAppDO.isTbMandatory() ? "1" : "0");
                        prepStmt.execute();
                        connection.commit();
                    }
                }
            } catch (SQLException e) {
                throw handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_APP, e);
            } catch (IdentityOAuth2Exception e) {
                throw handleError("Error occurred while processing the client id and client secret by " +
                        "TokenPersistenceProcessor", null);
            }
        } else {
            String message = "Error when adding the application. An application with the same name already exists.";
            throw handleError(message, null);
        }
    }

    public String[] addOAuthConsumer(String username, int tenantId, String userDomain) throws IdentityOAuthAdminException {
        String consumerKey;
        String consumerSecret = OAuthUtil.getRandomNumber();
        long userAccessTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getUserAccessTokenValidityPeriodInSeconds();
        long applicationAccessTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getApplicationAccessTokenValidityPeriodInSeconds();
        long refreshTokenExpireTime = OAuthServerConfiguration.getInstance()
                .getRefreshTokenValidityPeriodInSeconds();

        do {
            consumerKey = OAuthUtil.getRandomNumber();
        }
        while (isDuplicateConsumer(consumerKey));

        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER)) {
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
            prepStmt.execute();

            connection.commit();

        } catch (SQLException e) {
            String sqlStmt = SQLQueries.OAuthAppDAOSQLQueries.ADD_OAUTH_CONSUMER;
            throw handleError("Error when executing the SQL : " + sqlStmt, e);
        }
        return new String[]{consumerKey, consumerSecret};
    }

    public OAuthAppDO[] getOAuthConsumerAppsOfUser(String username, int tenantId) throws IdentityOAuthAdminException {
        OAuthAppDO[] oauthAppsOfUser;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
            String tenantDomain = realmService.getTenantManager().getDomain(tenantId);
            String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(username);
            String tenantQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUserName, tenantDomain);
            boolean isUsernameCaseSensitive = isUsernameCaseSensitive(tenantQualifiedUsername);
            boolean isPKCESupportEnabled = OAuth2ServiceComponentHolder.isPkceEnabled();

            String sql;
            if (isPKCESupportEnabled) {
                sql = SQLQueries.OAuthAppDAOSQLQueries.GET_CONSUMER_APPS_OF_USER_WITH_PKCE;
            } else {
                sql = SQLQueries.OAuthAppDAOSQLQueries.GET_CONSUMER_APPS_OF_USER;
            }

            if (!isUsernameCaseSensitive) {
                sql = sql.replace(USERNAME, LOWER_USERNAME);
            }
            try (PreparedStatement prepStmt = connection.prepareStatement(sql)) {
                prepStmt.setString(1, UserCoreUtil.removeDomainFromName(tenantAwareUserName));
                prepStmt.setString(2, IdentityUtil.extractDomainFromName(tenantAwareUserName));
                prepStmt.setInt(3, tenantId);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    List<OAuthAppDO> oauthApps = new ArrayList<>();
                    while (rSet.next()) {
                        if (rSet.getString(3) != null && rSet.getString(3).length() > 0) {
                            OAuthAppDO oauthApp = new OAuthAppDO();
                            oauthApp.setOauthConsumerKey(persistenceProcessor.getPreprocessedClientId(rSet.getString(1)));
                            oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(2)));
                            oauthApp.setApplicationName(rSet.getString(3));
                            oauthApp.setOauthVersion(rSet.getString(4));
                            oauthApp.setCallbackUrl(rSet.getString(5));
                            oauthApp.setGrantTypes(rSet.getString(6));
                            oauthApp.setId(rSet.getInt(7));
                            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                            authenticatedUser.setUserName(rSet.getString(8));
                            authenticatedUser.setTenantDomain(IdentityTenantUtil.getTenantDomain(rSet.getInt(9)));
                            authenticatedUser.setUserStoreDomain(rSet.getString(10));
                            if (isPKCESupportEnabled) {
                                oauthApp.setPkceMandatory(!"0".equals(rSet.getString(11)));
                                oauthApp.setPkceSupportPlain(!"0".equals(rSet.getString(12)));
                                oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(13));
                                oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(14));
                                oauthApp.setRefreshTokenExpiryTime(rSet.getLong(15));
                                oauthApp.setTbMandatory("0".equals(rSet.getString(16)) ? false : true);
                            } else {
                                oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(11));
                                oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(12));
                                oauthApp.setRefreshTokenExpiryTime(rSet.getLong(13));
                                oauthApp.setTbMandatory("0".equals(rSet.getString(14)) ? false : true);
                            }
                            oauthApp.setUser(authenticatedUser);
                            oauthApps.add(oauthApp);
                        }
                    }
                    oauthAppsOfUser = oauthApps.toArray(new OAuthAppDO[oauthApps.size()]);
                    connection.commit();
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

    public OAuthAppDO getAppInformation(String consumerKey) throws InvalidOAuthClientException, IdentityOAuth2Exception {

        OAuthAppDO oauthApp = null;
        boolean isPKCESupportEnabled = OAuth2ServiceComponentHolder.isPkceEnabled();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sqlQuery;
            if (isPKCESupportEnabled) {
                sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_WITH_PKCE;
            } else {
                sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO;
            }

            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    /**
                     * We need to determine whether the result set has more than 1 row. Meaning, we found an application for
                     * the given consumer key. There can be situations where a user passed a key which doesn't yet have an
                     * associated application. We need to barf with a meaningful error message for this case
                     */
                    boolean rSetHasRows = false;
                    while (rSet.next()) {
                        // There is at least one application associated with a given key
                        rSetHasRows = true;
                        if (rSet.getString(4) != null && rSet.getString(4).length() > 0) {
                            oauthApp = new OAuthAppDO();
                            oauthApp.setOauthConsumerKey(consumerKey);
                            oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(1)));
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
                            if (isPKCESupportEnabled) {
                                oauthApp.setPkceMandatory(!"0".equals(rSet.getString(10)));
                                oauthApp.setPkceSupportPlain(!"0".equals(rSet.getString(11)));
                                oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(12));
                                oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(13));
                                oauthApp.setRefreshTokenExpiryTime(rSet.getLong(14));
                                oauthApp.setTbMandatory("0".equals(rSet.getString(15)) ? false : true);
                            } else {
                                oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(10));
                                oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(11));
                                oauthApp.setRefreshTokenExpiryTime(rSet.getLong(12));
                                oauthApp.setTbMandatory("0".equals(rSet.getString(13)) ? false : true);
                            }
                        }
                    }
                    if (!rSetHasRows) {
                        /**
                         * We come here because user submitted a key that doesn't have any associated application with it.
                         * We're throwing an error here because we cannot continue without this info. Otherwise it'll throw
                         * a null values not supported error when it tries to cache this info
                         */

                        String message = "Cannot find an application associated with the given consumer key : " + consumerKey;
                        if (log.isDebugEnabled()) {
                            log.debug(message);
                        }
                        throw new InvalidOAuthClientException(message);
                    }
                    connection.commit();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the app information", e);
        }
        return oauthApp;
    }

    public OAuthAppDO getAppInformationByAppName(String appName) throws InvalidOAuthClientException, IdentityOAuth2Exception {
        OAuthAppDO oauthApp;
        boolean isPKCESupportEnabled = OAuth2ServiceComponentHolder.isPkceEnabled();

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
            String sqlQuery;
            if (isPKCESupportEnabled) {
                sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_BY_APP_NAME_WITH_PKCE;
            } else {
                sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.GET_APP_INFO_BY_APP_NAME;
            }

            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                prepStmt.setString(1, appName);
                prepStmt.setInt(2, tenantID);

                try (ResultSet rSet = prepStmt.executeQuery()) {
                    oauthApp = new OAuthAppDO();
                    oauthApp.setApplicationName(appName);
                    AuthenticatedUser user = new AuthenticatedUser();
                    user.setTenantDomain(IdentityTenantUtil.getTenantDomain(tenantID));
                    /**
                     * We need to determine whether the result set has more than 1 row. Meaning, we found an application for
                     * the given consumer key. There can be situations where a user passed a key which doesn't yet have an
                     * associated application. We need to barf with a meaningful error message for this case
                     */
                    boolean rSetHasRows = false;
                    while (rSet.next()) {
                        // There is at least one application associated with a given key
                        rSetHasRows = true;
                        if (rSet.getString(4) != null && rSet.getString(4).length() > 0) {
                            oauthApp.setOauthConsumerSecret(persistenceProcessor.getPreprocessedClientSecret(rSet.getString(1)));
                            user.setUserName(rSet.getString(2));
                            user.setUserStoreDomain(rSet.getString(3));
                            oauthApp.setUser(user);
                            oauthApp.setOauthConsumerKey(persistenceProcessor.getPreprocessedClientId(rSet.getString(4)));
                            oauthApp.setOauthVersion(rSet.getString(5));
                            oauthApp.setCallbackUrl(rSet.getString(6));
                            oauthApp.setGrantTypes(rSet.getString(7));
                            oauthApp.setId(rSet.getInt(8));
                            if (isPKCESupportEnabled) {
                                oauthApp.setPkceMandatory(!"0".equals(rSet.getString(9)));
                                oauthApp.setPkceSupportPlain(!"0".equals(rSet.getString(10)));
                                oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(11));
                                oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(12));
                                oauthApp.setRefreshTokenExpiryTime(rSet.getLong(13));
                                oauthApp.setTbMandatory("0".equals(rSet.getString(14)) ? false : true);
                            } else {
                                oauthApp.setUserAccessTokenExpiryTime(rSet.getLong(9));
                                oauthApp.setApplicationAccessTokenExpiryTime(rSet.getLong(10));
                                oauthApp.setRefreshTokenExpiryTime(rSet.getLong(11));
                                oauthApp.setTbMandatory("0".equals(rSet.getString(12)) ? false : true);
                            }
                        }
                    }
                    if (!rSetHasRows) {
                        /**
                         * We come here because user submitted a key that doesn't have any associated application with it.
                         * We're throwing an error here because we cannot continue without this info. Otherwise it'll throw
                         * a null values not supported error when it tries to cache this info
                         */
                        String message = "Cannot find an application associated with the given consumer key : " + appName;
                        if (log.isDebugEnabled()) {
                            log.debug(message);
                        }
                        throw new InvalidOAuthClientException(message);
                    }
                    connection.commit();
                }
            }
        } catch (SQLException e) {
            throw new IdentityOAuth2Exception("Error while retrieving the app information", e);
        }
        return oauthApp;
    }

    public void updateConsumerApplication(OAuthAppDO oauthAppDO) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            String sqlQuery;
            if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP_WITH_PKCE;
            } else {
                sqlQuery = SQLQueries.OAuthAppDAOSQLQueries.UPDATE_CONSUMER_APP;
            }

            try (PreparedStatement prepStmt = connection.prepareStatement(sqlQuery)) {
                prepStmt.setString(1, oauthAppDO.getApplicationName());
                prepStmt.setString(2, oauthAppDO.getCallbackUrl());
                prepStmt.setString(3, oauthAppDO.getGrantTypes());
                if (OAuth2ServiceComponentHolder.isPkceEnabled()) {
                    prepStmt.setString(4, oauthAppDO.isPkceMandatory() ? "1" : "0");
                    prepStmt.setString(5, oauthAppDO.isPkceSupportPlain() ? "1" : "0");
                    prepStmt.setLong(6, oauthAppDO.getUserAccessTokenExpiryTime());
                    prepStmt.setLong(7, oauthAppDO.getApplicationAccessTokenExpiryTime());
                    prepStmt.setLong(8, oauthAppDO.getRefreshTokenExpiryTime());
                    prepStmt.setString(9, oauthAppDO.isTbMandatory() ? "1" : "0");
                    prepStmt.setString(10, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
                    prepStmt.setString(11, persistenceProcessor.getProcessedClientSecret(oauthAppDO
                            .getOauthConsumerSecret()));
                } else {
                    prepStmt.setLong(4, oauthAppDO.getUserAccessTokenExpiryTime());
                    prepStmt.setLong(5, oauthAppDO.getApplicationAccessTokenExpiryTime());
                    prepStmt.setLong(6, oauthAppDO.getRefreshTokenExpiryTime());
                    prepStmt.setString(7, oauthAppDO.isTbMandatory() ? "1" : "0");
                    prepStmt.setString(8, persistenceProcessor.getProcessedClientId(oauthAppDO.getOauthConsumerKey()));
                    prepStmt.setString(9, persistenceProcessor.getProcessedClientSecret(oauthAppDO
                            .getOauthConsumerSecret()));
                }

                int count = prepStmt.executeUpdate();
                if (log.isDebugEnabled()) {
                    log.debug("No. of records updated for updating consumer application. : " + count);
                }
                connection.commit();
            }
        } catch (SQLException e) {
            throw handleError("Error when updating OAuth application", e);
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while processing client id and client secret by TokenPersistenceProcessor", e);
        }
    }

    public void removeConsumerApplication(String consumerKey) throws IdentityOAuthAdminException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); PreparedStatement
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.REMOVE_APPLICATION)) {
            prepStmt.setString(1, consumerKey);
            prepStmt.execute();
            connection.commit();
        } catch (SQLException e) {
            throw  handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries.REMOVE_APPLICATION, e);
        }
    }

    /**
     * Update the OAuth service provider name.
     * @param appName Service provider name.
     * @param consumerKey Consumer key.
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     */
    public void updateOAuthConsumerApp(String appName, String consumerKey)
            throws IdentityApplicationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); PreparedStatement
                statement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_OAUTH_INFO)) {
            statement.setString(1, appName);
            statement.setString(2, consumerKey);
            statement.execute();
            connection.setAutoCommit(false);
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        }
    }

    public String getConsumerAppState(String consumerKey) throws IdentityOAuthAdminException {
        String consumerAppState = null;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); PreparedStatement
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.GET_APPLICATION_STATE)) {

            prepStmt.setString(1, consumerKey);
            try (ResultSet rSet = prepStmt.executeQuery()) {
                if (rSet.next()) {
                    consumerAppState = rSet.getString(APP_STATE);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No App found for the consumerKey: " + consumerKey);
                    }
                }
                connection.commit();
            }
        } catch (SQLException e) {
            throw handleError("Error while executing the SQL prepStmt.", e);
        }
        return consumerAppState;
    }

    public void updateConsumerAppState(String consumerKey, String state) throws IdentityApplicationManagementException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); PreparedStatement
                statement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_APPLICATION_STATE)) {
            statement.setString(1, state);
            statement.setString(2, consumerKey);
            statement.execute();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        }
    }

    private boolean isDuplicateApplication(String username, int tenantId, String userDomain, OAuthAppDO consumerAppDTO)
            throws IdentityOAuthAdminException {

        boolean isDuplicateApp = false;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(username, tenantId);

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
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
                    connection.commit();
                }
            }
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL : " + SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_APPLICATION, e);
        }
        return isDuplicateApp;
    }

    private boolean isDuplicateConsumer(String consumerKey) throws IdentityOAuthAdminException {

        boolean isDuplicateConsumer = false;

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(); PreparedStatement
                prepStmt = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_CONSUMER)) {
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));

            try (ResultSet rSet = prepStmt.executeQuery()) {
                if (rSet.next()) {
                    isDuplicateConsumer = true;
                }
                connection.commit();
            }
        } catch (IdentityOAuth2Exception e) {
            throw handleError("Error occurred while processing the client id by TokenPersistenceProcessor", null);
        } catch (SQLException e) {
            throw handleError("Error when executing the SQL: " + SQLQueries.OAuthAppDAOSQLQueries.CHECK_EXISTING_CONSUMER, e);
        }
        return isDuplicateConsumer;
    }

    private boolean isUsernameCaseSensitive(String tenantQualifiedUsername) {
        return IdentityUtil.isUserStoreInUsernameCaseSensitive(tenantQualifiedUsername);
    }
}
