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

import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.dao.CacheBackedScopeClaimMappingDAOImpl;
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
    private AccessTokenDAO nonPersistedTokenDAO;
    private OAuthUserConsentedScopesDAO oauthUserConsentedScopesDAO;

    public OAuthTokenPersistenceFactory() {

        this.authorizationCodeDAO = new AuthorizationCodeDAOImpl();
        this.tokenDAO = new AccessTokenDAOImpl();
        this.scopeDAO = new OAuthScopeDAOImpl();
        this.managementDAO = new TokenManagementDAOImpl();
        this.requestObjectDAO = new RequestObjectDAOImpl();
        this.scopeClaimMappingDAO = new CacheBackedScopeClaimMappingDAOImpl();
        this.tokenBindingMgtDAO = new TokenBindingMgtDAOImpl();
        this.nonPersistedTokenDAO = new NonPersistentAccessTokenDAOImpl();
        this.oauthUserConsentedScopesDAO = new CacheBackedOAuthUserConsentedScopesDAOImpl();
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
    public AccessTokenDAO getAccessTokenDAO() {

        AccessTokenDAO accessTokenDAO = OAuth2ServiceComponentHolder.getInstance().getAccessTokenDAOService();
        if (accessTokenDAO == null) {
            return tokenDAO;
        }
        return accessTokenDAO;
    }

    public OAuthScopeDAO getOAuthScopeDAO() {

        return scopeDAO;
    }

    public TokenManagementDAO getTokenManagementDAO() {

        TokenManagementDAO tokenManagementDAO = OAuth2ServiceComponentHolder.getInstance()
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

    public AccessTokenDAO getAccessTokenDAOImpl(String consumerKey) {

        if (OAuth2Util.isNonPersistentTokenEnabled(consumerKey)) {
            return nonPersistedTokenDAO;
        }
        return tokenDAO;
    }
}
