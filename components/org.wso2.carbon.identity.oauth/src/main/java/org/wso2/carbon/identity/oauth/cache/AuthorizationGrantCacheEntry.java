/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.model.FederatedTokenDO;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Contains authenticated user attributes and nonce value.
 */
public class AuthorizationGrantCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -3043225645166013281L;

    private String codeId;

    private String authorizationCode;

    private String tokenId;

    private Map<ClaimMapping, String> userAttributes;

    private String nonceValue;

    private String pkceCodeChallenge;

    private String pkceCodeChallengeMethod;

    private LinkedHashSet acrValue;

    private String selectedAcrValue;

    private List<String> amrList = new ArrayList<>();

    private String essentialClaims;

    private long authTime;

    private long maxAge;

    private RequestObject requestObject;

    private boolean hasNonOIDCClaims;

    /*
        OIDC sub claim. This should be formatted based on the Service Provider configurations to append
        userStoreDomain and tenantDomain.
     */
    private String subjectClaim;

    private String tokenBindingValue;

    private String sessionContextIdentifier;

    private String oidcSessionId;

    private boolean isRequestObjectFlow;
    private AccessTokenExtendedAttributes accessTokenExtendedAttributes;
    private boolean isApiBasedAuthRequest;

    private List<FederatedTokenDO> federatedTokens;

    private List<String> audiences;

    private Map<String, Object> customClaims;

    private boolean isPreIssueAccessTokenActionsExecuted;

    public String getSubjectClaim() {
        return subjectClaim;
    }

    public void setSubjectClaim(String subjectClaim) {
        this.subjectClaim = subjectClaim;
    }

    public RequestObject getRequestObject() {
        return requestObject;
    }

    public void setRequestObject(RequestObject requestObject) {
        this.requestObject = requestObject;
    }

    public String getEssentialClaims() {
        return essentialClaims;
    }

    public void setEssentialClaims(String essentialClaims) {
        this.essentialClaims = essentialClaims;
    }

    public LinkedHashSet getAcrValue() {
        return acrValue;
    }

    public void setAcrValue(LinkedHashSet acrValue) {
        this.acrValue = acrValue;
    }

    public String getSelectedAcrValue() {
        return selectedAcrValue;
    }

    public void setSelectedAcrValue(String selectedAcrValue) {
        this.selectedAcrValue = selectedAcrValue;
    }

    public long getAuthTime() {
        return authTime;
    }

    public void setAuthTime(long authTime) {
        this.authTime = authTime;
    }

    public long getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(long maxAge) {
        this.maxAge = maxAge;
    }

    public AuthorizationGrantCacheEntry(Map<ClaimMapping, String> userAttributes) {
        this.userAttributes = userAttributes;
    }

    public AuthorizationGrantCacheEntry() {

    }

    public String getNonceValue() {
        return nonceValue;
    }

    public void setNonceValue(String nonceValue) {
        this.nonceValue = nonceValue;
    }

    public Map<ClaimMapping, String> getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(Map<ClaimMapping, String> userAttributes) {
        this.userAttributes = userAttributes;
    }

    public String getCodeId() {

        return codeId;
    }

    public void setCodeId(String codeId) {

        this.codeId = codeId;
    }

    public String getTokenId() {

        return tokenId;
    }

    public void setTokenId(String tokenId) {

        this.tokenId = tokenId;
    }

    public String getPkceCodeChallenge() {
        return pkceCodeChallenge;
    }

    public void setPkceCodeChallenge(String pkceCodeChallenge) {
        this.pkceCodeChallenge = pkceCodeChallenge;
    }

    public String getPkceCodeChallengeMethod() {
        return pkceCodeChallengeMethod;
    }

    public void setPkceCodeChallengeMethod(String pkceCodeChallengeMethod) {
        this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
    }

    public List<FederatedTokenDO> getFederatedTokens() {

        return federatedTokens;
    }

    public void setFederatedTokens(List<FederatedTokenDO> federatedTokens) {

        this.federatedTokens = federatedTokens;
    }

    /**
     * To check whether particular cache entry has non OIDC claims in it.
     *
     * @return true if the cache entry has non OIDC claims
     */
    public boolean isHasNonOIDCClaims() {
        return hasNonOIDCClaims;
    }

    /**
     * To set hasNonOIDCClaims.
     */
    public void setHasNonOIDCClaims(boolean hasNonOIDCClaims) {
        this.hasNonOIDCClaims = hasNonOIDCClaims;
    }

    /**
     * Adds authentication method reference to AMR.
     *
     * @param reference any string representation of an authentication method.
     */
    public void addAmr(String reference) {
        amrList.add(reference);
    }

    /**
     * Returns a list of Authentication Method references.
     *
     * @return an unmodifiable list of internal AMR list.
     */
    public List<String> getAmrList() {
        return Collections.unmodifiableList(amrList);
    }

    /**
     * Get token binding value.
     *
     * @return token binding value.
     */
    public String getTokenBindingValue() {

        return tokenBindingValue;
    }

    /**
     * Set token binding value.
     *
     * @param tokenBindingValue
     */
    public void setTokenBindingValue(String tokenBindingValue) {

        this.tokenBindingValue = tokenBindingValue;
    }

    /**
     * Get sessionContextIdentifier value.
     *
     * @return sessionContextIdentifier value.
     */
    public String getSessionContextIdentifier() {

        return sessionContextIdentifier;
    }

    /**
     * Set sessionContextIdentifier value. This can be used to add sessionContext identifier into the idtoken.
     * Hence it will be used when extending the idp session.
     *
     * @param sessionContextIdentifier sessionContextIdentifier.
     */
    public void setSessionContextIdentifier(String sessionContextIdentifier) {

        this.sessionContextIdentifier = sessionContextIdentifier;
    }

    /**
     * Set OIDC session Id value. This can be used to add sid claim into the id_token for the back channel logout.
     *
     * @param oidcSessionId OIDC session Id value.
     */
    public void setOidcSessionId(String oidcSessionId) {

        this.oidcSessionId = oidcSessionId;
    }

    /**
     *  Get OIDC session Id value.
     *
     * @return  OIDC session Id value.
     */
    public String getOidcSessionId() {

        return oidcSessionId;
    }

    public void setAuthorizationCode(String code) {

        this.authorizationCode = code;
    }

    public String getAuthorizationCode() {

        return authorizationCode;
    }


    /**
     *
     * @return  Whether the flow has request object or not.
     */
    public boolean isRequestObjectFlow() {

        return isRequestObjectFlow;
    }

    /**
     * Sets whether the the flow has request object or not.
     *
     * @param isRequestObjectFlow   Is flow has request object or not.
     */
    public void setRequestObjectFlow(boolean isRequestObjectFlow) {

        this.isRequestObjectFlow = isRequestObjectFlow;
    }

    public AccessTokenExtendedAttributes getAccessTokenExtensionDO() {

        return accessTokenExtendedAttributes;
    }

    public void setAccessTokenExtensionDO(AccessTokenExtendedAttributes accessTokenExtendedAttributes) {

        this.accessTokenExtendedAttributes = accessTokenExtendedAttributes;
    }

    public boolean isApiBasedAuthRequest() {

        return isApiBasedAuthRequest;
    }

    public void setApiBasedAuthRequest(boolean apiBasedAuthRequest) {

        isApiBasedAuthRequest = apiBasedAuthRequest;
    }

    public List<String> getAudiences() {

        return audiences;
    }

    public void setAudiences(List<String> audiences) {

        this.audiences = audiences;
    }

    public Map<String, Object> getCustomClaims() {

        return customClaims;
    }

    public void setCustomClaims(Map<String, Object> customClaims) {

        this.customClaims = customClaims;
    }

    public boolean isPreIssueAccessTokenActionsExecuted() {

        return isPreIssueAccessTokenActionsExecuted;
    }

    public void setPreIssueAccessTokenActionsExecuted(boolean preIssueAccessTokenActionsExecuted) {

        isPreIssueAccessTokenActionsExecuted = preIssueAccessTokenActionsExecuted;
    }
}
