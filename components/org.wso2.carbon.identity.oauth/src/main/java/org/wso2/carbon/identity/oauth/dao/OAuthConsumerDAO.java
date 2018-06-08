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
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.Parameters;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class OAuthConsumerDAO {

    public static final Log log = LogFactory.getLog(OAuthConsumerDAO.class);
    private TokenPersistenceProcessor persistenceProcessor;
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    public OAuthConsumerDAO() {

        try {
            persistenceProcessor = OAuthServerConfiguration.getInstance().getPersistenceProcessor();
        } catch (IdentityOAuth2Exception e) {
            log.error("Error retrieving TokenPersistenceProcessor. Defaulting to PlainTextProcessor", e);
            persistenceProcessor = new PlainTextPersistenceProcessor();
        }

    }

    /**
     * Returns the consumer secret corresponding to a given consumer key
     *
     * @param consumerKey Consumer key
     * @return consumer secret
     * @throws IdentityOAuthAdminException Error when reading consumer secret from the persistence store
     */
    public String getOAuthConsumerSecret(String consumerKey) throws IdentityOAuthAdminException {
        String consumerSecret = null;
        if (isHashDisabled) {
            Connection connection = IdentityDatabaseUtil.getDBConnection();
            PreparedStatement prepStmt = null;
            ResultSet resultSet = null;

            try {
                prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.GET_CONSUMER_SECRET);
                prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
                resultSet = prepStmt.executeQuery();

                if (resultSet.next()) {
                        consumerSecret = persistenceProcessor.getPreprocessedClientSecret(resultSet.getString(1));
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid Consumer Key : " + consumerKey);
                    }
                }
                connection.commit();
            } catch (SQLException e) {
                throw new IdentityOAuthAdminException("Error when reading the consumer secret for consumer key : " +
                        consumerKey, e);
            } catch (IdentityOAuth2Exception e) {
                throw new IdentityOAuthAdminException("Error occurred while processing client id and client secret by " +
                        "TokenPersistenceProcessor", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Consumer secret hashing enabled. Returning client secret as null.");
            }
        }

        return consumerSecret;

    }

    /**
     * Check whether the provided consumerKey, consumerSecret combination is exist or not in the database.
     *
     * @param consumerKey Consumer key.
     * @param consumerSecret Consumer secret.
     * @return Check the provided consumerKey, consumerSecret combination is exist or not.
     * @throws IdentityOAuthAdminException Error when reading consumer key, consumer secret from the database.
     */
    public boolean isConsumerSecretExist(String consumerKey, String consumerSecret)
            throws IdentityOAuthAdminException {

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Connection connection = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            String consumerSecretHash = persistenceProcessor.getProcessedClientSecret(consumerSecret);
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.EXISTENCE_OF_CONSUMER_SECRET);
            prepStmt.setString(1, persistenceProcessor.getProcessedClientId(consumerKey));
            prepStmt.setString(2, consumerSecretHash);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Invalid Consumer Secret : %s for Consumer Key : %s", consumerSecret,
                            consumerKey));
                }
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when reading the consumer key for consumer secret : " +
                    consumerSecret, e);
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuthAdminException("Error occurred while processing client secret ", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return false;

    }

    public void updateSecretKey(String consumerKey, String newSecretKey) throws IdentityApplicationManagementException {
        PreparedStatement statement = null;
        Connection connection = null;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            statement = connection.prepareStatement(SQLQueries.OAuthAppDAOSQLQueries.UPDATE_OAUTH_SECRET_KEY);
            statement.setString(1, newSecretKey);
            statement.setString(2, consumerKey);
            statement.execute();
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityApplicationManagementException("Error while executing the SQL statement.", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, statement);
        }
    }

    /**
     * Returns the username corresponding to a given client id and consumer secret
     *
     * @param clientId     Client Id/Key
     * @param clientSecret Consumer secret
     * @return Username if successful, empty string otherwise
     * @throws IdentityOAuthAdminException Error when reading consumer secret from the persistence store
     */
    public String getAuthenticatedUsername(String clientId, String clientSecret) throws IdentityOAuthAdminException {
        String username = "";
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.GET_USERNAME_FOR_KEY_AND_SECRET);
            prepStmt.setString(1, clientId);
            prepStmt.setString(2, clientSecret);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                username = resultSet.getString(1);
            } else {
                log.debug("Invalid client id : " + clientId);
            }
            connection.commit();
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + SQLQueries.OAuthConsumerDAOSQLQueries.GET_USERNAME_FOR_KEY_AND_SECRET);
            log.error(e.getMessage(), e);
            throw new IdentityOAuthAdminException("Error while reading username for client id : " + clientId +
                    ", and consumer secret : " + clientSecret);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return username;

    }

    /**
     * Get the token secret for the given access token
     *
     * @param token         OAuth token, this could be a request token(temporary token) or a access token
     * @param isAccessToken True, if it is as access token
     * @return Token Secret
     * @throws IdentityOAuthAdminException Error when accessing the token secret from the persistence store.
     */
    public String getOAuthTokenSecret(String token, Boolean isAccessToken) throws IdentityException {

        String tokenSecret = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sqlStmt;

        if (isAccessToken) {
            sqlStmt = SQLQueries.OAuthConsumerDAOSQLQueries.GET_ACCESS_TOKEN_SECRET;
        } else {
            sqlStmt = SQLQueries.OAuthConsumerDAOSQLQueries.GET_REQ_TOKEN_SECRET;
        }

        try {
            prepStmt = connection.prepareStatement(sqlStmt);
            prepStmt.setString(1, token);
            resultSet = prepStmt.executeQuery();
            connection.commit();

            if (resultSet.next()) {
                tokenSecret = resultSet.getString(1);
            } else {
                throw IdentityException.error("Invalid token : " + token);
            }
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when reading the token secret for token : " +
                    token, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return tokenSecret;

    }

    /**
     * Creates a new OAuth token.
     *
     * @param consumerKey  Consumer Key
     * @param oauthToken   OAuth Token, a unique identifier
     * @param oauthSecret  OAuth Secret
     * @param userCallback Where the user should be redirected once the approval completed.
     * @param scope        Resource or the scope of the resource.
     * @throws IdentityOAuthAdminException Error when writing the OAuth Req. token to the persistence store
     */
    public void createOAuthRequestToken(String consumerKey, String oauthToken, String oauthSecret,
                                        String userCallback, String scope) throws IdentityOAuthAdminException {
        final String OUT_OF_BAND = "oob";
        if (userCallback == null || OUT_OF_BAND.equals(userCallback)) {
            userCallback = getCallbackURLOfApp(consumerKey);
        }

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.ADD_OAUTH_REQ_TOKEN);
            prepStmt.setString(1, oauthToken);
            prepStmt.setString(2, oauthSecret);
            prepStmt.setString(3, userCallback);
            prepStmt.setString(4, scope);
            prepStmt.setString(5, Boolean.toString(false));
            prepStmt.setString(6, consumerKey);

            prepStmt.execute();
            connection.commit();

        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + SQLQueries.OAuthConsumerDAOSQLQueries.ADD_OAUTH_REQ_TOKEN);
            log.error(e.getMessage(), e);
            throw new IdentityOAuthAdminException("Error when creating the request token for consumer : " + consumerKey);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

    }

    /**
     * Authorizes the OAuth request token.
     *
     * @param oauthToken    Authorized OAuth token
     * @param userName      The name of the user who authorized the token.
     * @param oauthVerifier oauth_verifier - an unique identifier
     * @throws IdentityException
     */
    public Parameters authorizeOAuthToken(String oauthToken, String userName, String oauthVerifier)
            throws IdentityException {
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.AUTHORIZE_REQ_TOKEN);
            prepStmt.setString(1, Boolean.toString(true));
            prepStmt.setString(2, oauthVerifier);
            prepStmt.setString(3, userName);
            prepStmt.setString(4, oauthToken);

            prepStmt.execute();
            connection.commit();

        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when authorizing the request token : " + oauthToken);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        Parameters params = new Parameters();
        params.setOauthCallback(getCallbackURLOfReqToken(oauthToken));

        return params;

    }

    public Parameters getRequestToken(String oauthToken) throws IdentityException {
        Parameters params = new Parameters();
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.GET_REQ_TOKEN);
            prepStmt.setString(1, oauthToken);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                params.setOauthToken(resultSet.getString(1));
                params.setOauthTokenSecret(resultSet.getString(2));
                params.setOauthConsumerKey(resultSet.getString(3));
                params.setOauthCallback(resultSet.getString(4));
                params.setScope(resultSet.getString(5));
                params.setOauthTokenVerifier(resultSet.getString(7));
                params.setAuthorizedbyUserName(resultSet.getString(8));

            } else {
                throw IdentityException.error("Invalid request token : " + oauthToken);
            }
            connection.commit();
        } catch (SQLException e) {
            throw IdentityException.error("Error when retrieving request token from the persistence store : " +
                    oauthToken);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return params;
    }

    public void issueAccessToken(String consumerKey, String accessToken, String accessTokenSecret,
                                 String requestToken, String authorizedUser, String scope) throws IdentityOAuthAdminException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement removeReqTokStmt = null;
        PreparedStatement issueAccessTokStmt = null;

        try {
            removeReqTokStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.REMOVE_REQUEST_TOKEN);
            removeReqTokStmt.setString(1, requestToken);
            removeReqTokStmt.execute();

            issueAccessTokStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.ADD_ACCESS_TOKEN);
            issueAccessTokStmt.setString(1, accessToken);
            issueAccessTokStmt.setString(2, accessTokenSecret);
            issueAccessTokStmt.setString(3, consumerKey);
            issueAccessTokStmt.setString(4, scope);
            issueAccessTokStmt.setString(5, authorizedUser);
            issueAccessTokStmt.execute();

            connection.commit();

        } catch (SQLException e) {
            log.error(e.getMessage(), e);
            throw new IdentityOAuthAdminException("Error when creating the request token for consumer : " + consumerKey);
        } finally {
            IdentityDatabaseUtil.closeStatement(issueAccessTokStmt);
            IdentityDatabaseUtil.closeAllConnections(connection, null, removeReqTokStmt);
        }

    }

    /**
     * Validating the access token. Should be equal in the scope where the original request token
     * been issued to.If this matches, the method returns the user who authorized the request token.
     *
     * @param consumerKey Consumer Key
     * @param oauthToken  Access Token
     * @param reqScope    Scope in the request
     * @return Authorized Username
     * @throws IdentityException Error when reading token information from persistence store or invalid token or invalid scope.
     */
    public String validateAccessToken(String consumerKey, String oauthToken, String reqScope)
            throws IdentityException {

        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String scope = null;
        String authorizedUser = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.GET_ACCESS_TOKEN);
            prepStmt.setString(1, oauthToken);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                scope = resultSet.getString(1);
                authorizedUser = resultSet.getString(2);
            } else {
                throw IdentityException.error("Invalid access token : " + oauthToken);
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when reading the callback url for consumer key : " +
                    consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        if (reqScope != null && reqScope.equals(scope)) {
            return authorizedUser;
        } else {
            throw IdentityException.error("Scope of the access token doesn't match with the original scope");
        }
    }

    private String getCallbackURLOfApp(String consumerKey) throws IdentityOAuthAdminException {
        String callbackURL = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.GET_REGISTERED_CALLBACK_URL);
            prepStmt.setString(1, consumerKey);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                callbackURL = resultSet.getString(1);
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when reading the callback url for consumer key : " +
                    consumerKey, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return callbackURL;
    }

    private String getCallbackURLOfReqToken(String oauthToken) throws IdentityOAuthAdminException {
        String callbackURL = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.OAuthConsumerDAOSQLQueries.GET_CALLBACK_URL_OF_REQ_TOKEN);
            prepStmt.setString(1, oauthToken);
            resultSet = prepStmt.executeQuery();

            if (resultSet.next()) {
                callbackURL = resultSet.getString(1);
            }
            connection.commit();
        } catch (SQLException e) {
            throw new IdentityOAuthAdminException("Error when reading the callback url for OAuth Token : " +
                    oauthToken, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }

        return callbackURL;
    }

}
