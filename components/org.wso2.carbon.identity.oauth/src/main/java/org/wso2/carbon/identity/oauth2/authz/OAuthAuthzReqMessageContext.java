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

package org.wso2.carbon.identity.oauth2.authz;

import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto.IDTokenDTO;

import java.io.Serializable;
import java.util.Properties;

/**
 * OAuth authorization request message context.
 */
public class OAuthAuthzReqMessageContext implements Serializable {

    private static final long serialVersionUID = -5196424918451611897L;
    // We set OAuth2AuthorizeReqDTO as transient because we don't want to serialize OAuth2AuthorizeReqDTO because
    // it contains cookies and request headers.
    private transient OAuth2AuthorizeReqDTO authorizationReqDTO;
    private String[] approvedScope;
    private String[] requestedScopes;
    private long validityPeriod;

    private long authorizationCodeValidityPeriod;

    private long accessTokenValidityPeriod;

    private long refreshTokenvalidityPeriod;

    private long accessTokenIssuedTime;

    private long refreshTokenIssuedTime;

    private long codeIssuedTime;

    private String[] authorizedInternalScopes;

    private boolean isConsentedToken;

    private boolean isImpersonationRequest;

    private boolean isSubjectTokenFlow;

    private Properties properties = new Properties();

    private AuthorizationDetails approvedAuthorizationDetails;

    private AuthorizationDetails requestedAuthorizationDetails;

    private boolean isPreIssueIDTokenActionExecuted;

    private IDTokenDTO preIssueIDTokenActionDTO;


    public OAuthAuthzReqMessageContext(OAuth2AuthorizeReqDTO authorizationReqDTO) {

        this.authorizationReqDTO = authorizationReqDTO;
    }

    public OAuth2AuthorizeReqDTO getAuthorizationReqDTO() {

        return authorizationReqDTO;
    }

    public void setAuthorizationReqDTO(OAuth2AuthorizeReqDTO authorizationReqDTO) {

        this.authorizationReqDTO = authorizationReqDTO;
    }

    public String[] getApprovedScope() {

        return approvedScope;
    }

    public void setApprovedScope(String[] approvedScope) {

        this.approvedScope = approvedScope;
    }

    /**
     * @return user requested scope list
     */
    public String[] getRequestedScopes() {

        return requestedScopes;
    }

    /**
     * @param requestedScopes user requested scopes list
     */
    public void setRequestedScopes(String[] requestedScopes) {

        this.requestedScopes = requestedScopes;
    }

    @Deprecated
    /**
     * @deprecated Avoid using this, use getAccessTokenValidityPeriod or getOAuthorizationCodeValidityPeriod instead
     */
    public long getValidityPeriod() {

        return validityPeriod;
    }

    @Deprecated
    /**
     * @deprecated Avoid using this, use setAccessTokenValidityPeriod or setOAuthorizationCodeValidityPeriod instead
     */
    public void setValidityPeriod(long validityPeriod) {

        this.validityPeriod = validityPeriod;
    }

    public long getAuthorizationCodeValidityPeriod() {

        return authorizationCodeValidityPeriod;
    }

    public void setAuthorizationCodeValidityPeriod(long oauthorizationCodeValidityPeriod) {

        this.authorizationCodeValidityPeriod = oauthorizationCodeValidityPeriod;
    }

    public long getAccessTokenValidityPeriod() {

        return accessTokenValidityPeriod;
    }

    public void setAccessTokenValidityPeriod(long accessTokenValidityPeriod) {

        this.accessTokenValidityPeriod = accessTokenValidityPeriod;
    }

    public void addProperty(Object propName, Object propValue) {

        properties.put(propName, propValue);
    }

    public Object getProperty(Object propName) {

        return properties.get(propName);
    }

    public long getRefreshTokenvalidityPeriod() {

        return refreshTokenvalidityPeriod;
    }

    public void setRefreshTokenvalidityPeriod(long refreshTokenvalidityPeriod) {

        this.refreshTokenvalidityPeriod = refreshTokenvalidityPeriod;
    }

    public long getAccessTokenIssuedTime() {

        return accessTokenIssuedTime;
    }

    public void setAccessTokenIssuedTime(long accessTokenIssuedTime) {

        this.accessTokenIssuedTime = accessTokenIssuedTime;
    }

    public long getRefreshTokenIssuedTime() {

        return refreshTokenIssuedTime;
    }

    public void setRefreshTokenIssuedTime(long refreshTokenIssuedTime) {

        this.refreshTokenIssuedTime = refreshTokenIssuedTime;
    }

    public long getCodeIssuedTime() {

        return codeIssuedTime;
    }

    public void setCodeIssuedTime(long codeIssuedTime) {

        this.codeIssuedTime = codeIssuedTime;
    }

    public String[] getAuthorizedInternalScopes() {
        return authorizedInternalScopes;
    }

    public void setAuthorizedInternalScopes(String[] authorizedInternalScopes) {
        this.authorizedInternalScopes = authorizedInternalScopes;
    }

    public boolean isConsentedToken() {

        return isConsentedToken;
    }

    public void setConsentedToken(boolean consentedToken) {

        isConsentedToken = consentedToken;
    }

    public boolean isImpersonationRequest() {

        return isImpersonationRequest;
    }

    public void setImpersonationRequest(boolean impersonationRequest) {

        isImpersonationRequest = impersonationRequest;
    }

    public boolean isSubjectTokenFlow() {

        return isSubjectTokenFlow;
    }

    public void setSubjectTokenFlow(boolean subjectTokenFlow) {

        isSubjectTokenFlow = subjectTokenFlow;
    }

    /**
     * Retrieves the user approved authorization details.
     *
     * @return the {@link AuthorizationDetails} instance representing the approved authorization information.
     * If no authorization details are available, it will return {@code null}.
     */
    public AuthorizationDetails getApprovedAuthorizationDetails() {

        return this.approvedAuthorizationDetails;
    }

    /**
     * Sets the approved authorization details.
     * This method updates the approved authorization details with the provided {@link AuthorizationDetails} instance.
     *
     * @param approvedAuthorizationDetails the approved {@link AuthorizationDetails} to set.
     */
    public void setApprovedAuthorizationDetails(final AuthorizationDetails approvedAuthorizationDetails) {

        this.approvedAuthorizationDetails = approvedAuthorizationDetails;
    }

    /**
     * Retrieves the requested authorization details.
     *
     * @return the {@link AuthorizationDetails} instance representing the authorization information came in the request.
     * If no authorization details are available, it will return {@code null}.
     */
    public AuthorizationDetails getRequestedAuthorizationDetails() {

        return this.requestedAuthorizationDetails;
    }

    /**
     * Sets the requested authorization details.
     * This method updates the requested authorization details with the provided {@link AuthorizationDetails} instance.
     *
     * @param requestedAuthorizationDetails the requested {@link AuthorizationDetails} to set.
     */
    public void setRequestedAuthorizationDetails(final AuthorizationDetails requestedAuthorizationDetails) {

        this.requestedAuthorizationDetails = requestedAuthorizationDetails;
    }

    public boolean isPreIssueIDTokenActionExecuted() {

        return isPreIssueIDTokenActionExecuted;
    }

    public void setPreIssueIDTokenActionExecuted(boolean isPreIssueIDTokenActionExecuted) {

        this.isPreIssueIDTokenActionExecuted = isPreIssueIDTokenActionExecuted;
    }

    public IDTokenDTO getPreIssueIDTokenActionDTO() {

        return preIssueIDTokenActionDTO;
    }

    public void setPreIssueIDTokenActionDTO(IDTokenDTO preIssueIDTokenActionDTO) {

        this.preIssueIDTokenActionDTO = preIssueIDTokenActionDTO;
    }
}
