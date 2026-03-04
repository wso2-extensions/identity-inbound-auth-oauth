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

import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.rar.dao.AuthorizationDetailsDAO;
import org.wso2.carbon.identity.oauth.rar.dao.AuthorizationDetailsDAOImpl;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.dao.CacheBackedUnifiedScopeMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectDAO;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectDAOImpl;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;

/**
 * OAUth token persistence factory.
 */
public class OAuthTokenPersistenceFactory {

    private static OAuthTokenPersistenceFactory factory = new OAuthTokenPersistenceFactory();
    private AuthorizationCodeDAO authorizationCodeDAO;
    private AccessTokenDAO tokenDAO;
    private OAuthScopeDAO scopeDAO;
    private TokenManagementDAO managementDAO;
    private RequestObjectDAO requestObjectDAO;
    private ScopeClaimMappingDAO scopeClaimMappingDAO;
    private TokenBindingMgtDAO tokenBindingMgtDAO;
    private OAuthUserConsentedScopesDAO oauthUserConsentedScopesDAO;
    private final AuthorizationDetailsDAO authorizationDetailsDAO;
    private final RevokedTokenPersistenceDAO revokedTokenPersistenceDAO;
    private final AccessTokenDAO nonPersistedTokenDAO;

    public OAuthTokenPersistenceFactory() {

        this.authorizationCodeDAO = new AuthorizationCodeDAOImpl();
        this.tokenDAO = new AccessTokenDAOImpl();
        this.scopeDAO = new OAuthScopeDAOImpl();
        this.managementDAO = new TokenManagementDAOImpl();
        this.requestObjectDAO = new RequestObjectDAOImpl();
        this.scopeClaimMappingDAO = new CacheBackedUnifiedScopeMappingDAOImpl();
        this.tokenBindingMgtDAO = new TokenBindingMgtDAOImpl();
        this.oauthUserConsentedScopesDAO = new CacheBackedOAuthUserConsentedScopesDAOImpl();
        this.authorizationDetailsDAO = new AuthorizationDetailsDAOImpl();
        this.revokedTokenPersistenceDAO = new RevokedTokenDAOImpl();
        this.nonPersistedTokenDAO = new NonPersistentAccessTokenDAOImpl();
    }

    public static OAuthTokenPersistenceFactory getInstance() {

        return factory;
    }

    public AuthorizationCodeDAO getAuthorizationCodeDAO() {

        return authorizationCodeDAO;
    }

    /**
     * @deprecated Use {@link #getAccessTokenDAOImpl(String)} instead.
     */
    @Deprecated
    public AccessTokenDAO getAccessTokenDAO() {

        AccessTokenDAO accessTokenDAO = OAuthComponentServiceHolder.getInstance().getAccessTokenDAOService();
        if (accessTokenDAO == null) {
            return tokenDAO;
        }

        return accessTokenDAO;
    }

    public OAuthScopeDAO getOAuthScopeDAO() {

        return scopeDAO;
    }

    public TokenManagementDAO getTokenManagementDAO() {

        TokenManagementDAO tokenManagementDAO = OAuthComponentServiceHolder.getInstance()
                .getTokenManagementDAOService();
        if (tokenManagementDAO == null) {
            return managementDAO;
        }
        return tokenManagementDAO;
    }

    public RequestObjectDAO getRequestObjectDAO() {

        return requestObjectDAO;
    }

    public ScopeClaimMappingDAO getScopeClaimMappingDAO() {

        return scopeClaimMappingDAO;
    }

    public TokenBindingMgtDAO getTokenBindingMgtDAO() {

        return tokenBindingMgtDAO;
    }

    public OAuthUserConsentedScopesDAO getOAuthUserConsentedScopesDAO() {

        return oauthUserConsentedScopesDAO;
    }

    /**
     * Retrieves the DAO for revoked token persistence.
     * <p>
     * This method returns a {@link RevokedTokenPersistenceDAO} instance that provides access to the
     * revoked token data. This DAO is used to interact with the underlying data store to manage revoked tokens,
     * including checking if a token is revoked and adding revoked tokens.
     *</p>
     * @return the {@link RevokedTokenPersistenceDAO} instance that provides access to revoked token data.
     */
    public RevokedTokenPersistenceDAO getRevokedTokenPersistenceDAO() {

        return revokedTokenPersistenceDAO;
    }

    /**
     * Retrieves the DAO for authorization details.
     * <p>
     * This method returns an {@link AuthorizationDetailsDAO} singleton instance that provides access to the
     * {@link AuthorizationDetails} data. This DAO is used to interact
     * with the underlying data store to fetch and manipulate authorization information.
     *</p>
     * @return the {@link AuthorizationDetailsDAO} instance that provides access to authorization details data.
     */
    public AuthorizationDetailsDAO getAuthorizationDetailsDAO() {
        return this.authorizationDetailsDAO;
    }

    /**
     * Retrieves the appropriate AccessTokenDAO implementation based on the consumer key.
     *
     * <p>
     * This method checks if non-persistent tokens are enabled for the given consumer key. If they are enabled,
     * it returns an instance of {@link NonPersistentAccessTokenDAOImpl}. Otherwise, it returns the default
     * {@link AccessTokenDAO} implementation.
     * </p>
     *
     * @param consumerKey The consumer key for which to retrieve the AccessTokenDAO implementation.
     * @return An instance of AccessTokenDAO based on the configuration for the given consumer key.
     */
    public AccessTokenDAO getAccessTokenDAOImpl(String consumerKey) {

        if (OAuth2Util.isNonPersistentTokenEnabled(consumerKey)) {
            return nonPersistedTokenDAO;
        }
        return getAccessTokenDAO();
    }
}
