/*
 * Copyright (c) 2013, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.cache;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.FederatedTokenDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Session data cache entry.
 */
public class SessionDataCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -7182270780665398094L;
    private AuthenticatedUser loggedInUser;
    private OAuth2Parameters oAuth2Parameters;
    private OAuthAuthzReqMessageContext authzReqMsgCtx;
    private long authTime;
    private String authenticatedIdPs;
    private String essentialClaims;
    private String sessionContextIdentifier;

   // Flag to indicate whether the entry needs to be removed once consumed.
    private boolean removeOnConsume = false;

    private String queryString = null;

    private ConcurrentMap<String, String[]> paramMap = new ConcurrentHashMap<String, String[]>();

    private Map<String, Serializable> endpointParams = new HashMap<>();
    private List<FederatedTokenDO> federatedTokens;

    public OAuthAuthzReqMessageContext getAuthzReqMsgCtx() {
        return authzReqMsgCtx;
    }

    public void setAuthzReqMsgCtx(OAuthAuthzReqMessageContext authzReqMsgCtx) {
        this.authzReqMsgCtx = authzReqMsgCtx;
    }

    public OAuth2Parameters getoAuth2Parameters() {
        return oAuth2Parameters;
    }

    public void setoAuth2Parameters(OAuth2Parameters oAuth2Parameters) {
        this.oAuth2Parameters = oAuth2Parameters;
    }

    public AuthenticatedUser getLoggedInUser() {
        return loggedInUser;
    }

    public void setLoggedInUser(AuthenticatedUser loggedInUser) {
        this.loggedInUser = loggedInUser;
    }

    public String getQueryString() {
        return queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    public Map<String, String[]> getParamMap() {
        return paramMap;
    }

    public void setParamMap(ConcurrentMap<String, String[]> paramMap) {
        this.paramMap = paramMap;
    }

    public String getAuthenticatedIdPs() {
        return authenticatedIdPs;
    }

    public void setAuthenticatedIdPs(String authenticatedIdPs) {
        this.authenticatedIdPs = authenticatedIdPs;
    }

    public long getAuthTime() {
        return authTime;
    }

    public void setAuthTime(long authTime) {
        this.authTime = authTime;
    }

    public String getEssentialClaims() {
        return essentialClaims;
    }

    public void setEssentialClaims(String essentialClaims) {
        this.essentialClaims = essentialClaims;
    }

    public Map<String, Serializable> getEndpointParams() {

        return endpointParams;
    }

    /**
     * Get sessionContextIdentifier.
     *
     * @return sessionContextIdentifier.
     */
    public String getSessionContextIdentifier() {

        return sessionContextIdentifier;
    }

    /**
     * Set sessionContextIdentifier.
     *
     * @param sessionContextIdentifier sessionContextIdentifier.
     */
    public void setSessionContextIdentifier(String sessionContextIdentifier) {

        this.sessionContextIdentifier = sessionContextIdentifier;
    }

    /**
     * Get removeOnConsume.
     *
     * @return removeOnConsume.
     */
    public boolean isRemoveOnConsume() {

        return removeOnConsume;
    }

    /**
     * Set removeOnConsume.
     *
     * @param removeOnConsume removeOnConsume.
     */
    public void setRemoveOnConsume(boolean removeOnConsume) {

        this.removeOnConsume = removeOnConsume;
    }

    public List<FederatedTokenDO> getFederatedTokens() {

        return federatedTokens;
    }

    public void setFederatedTokens(List<FederatedTokenDO> federatedTokens) {

        this.federatedTokens = federatedTokens;
    }
}
