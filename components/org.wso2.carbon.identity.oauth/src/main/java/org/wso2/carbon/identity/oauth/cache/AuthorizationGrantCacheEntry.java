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

    public String getCodeId(){
        return codeId;
    }

    public void setCodeId(String codeId){
        this.codeId = codeId;
    }

    public String getTokenId(){
        return tokenId;
    }

    public void setTokenId(String tokenId){
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
}
