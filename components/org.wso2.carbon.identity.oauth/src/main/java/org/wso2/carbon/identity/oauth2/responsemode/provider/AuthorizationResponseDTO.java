/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.responsemode.provider;

import javax.servlet.http.HttpServletResponse;


/**
 * An instance of this class can contain the authorization params of an authorization flow
 */
public class AuthorizationResponseDTO {

    private String signingTenantDomain;
    private String formPostRedirectPage;
    private String clientId;
    private String sessionState;
    private String state;
    private String authenticatedIDPs;
    private String redirectUrl;
    private String responseMode;
    private String responseType;
    private boolean isMtlsRequest;

    private int responseCode = HttpServletResponse.SC_FOUND;

    private SuccessResponseDTO successResponseDTO;
    private ErrorResponseDTO errorResponseDTO;
    private boolean isConsentRedirect;
    private boolean isForwardToOAuthResponseJSP;

    public AuthorizationResponseDTO() {

        this.successResponseDTO = new SuccessResponseDTO();
        this.isConsentRedirect = false;
        this.isForwardToOAuthResponseJSP = false;
    }

    public boolean getIsConsentRedirect() {

        return isConsentRedirect;
    }

    public void setIsConsentRedirect(boolean isConsentRedirect) {

        this.isConsentRedirect = isConsentRedirect;
    }

    public boolean getIsForwardToOAuthResponseJSP() {

        return isForwardToOAuthResponseJSP;
    }

    public void setIsForwardToOAuthResponseJSP(boolean isForwardToOAuthResponseJSP) {

        this.isForwardToOAuthResponseJSP = isForwardToOAuthResponseJSP;
    }

    public String getState() {

        return state;
    }

    public void setState(String state) {

        this.state = state;
    }

    public String getResponseType() {

        return responseType;
    }

    public void setResponseType(String responseType) {

        this.responseType = responseType;
    }

    public SuccessResponseDTO getSuccessResponseDTO() {

        return successResponseDTO;
    }

    public ErrorResponseDTO getErrorResponseDTO() {

        return errorResponseDTO;
    }

    public String getResponseMode() {

        return responseMode;
    }

    public void setResponseMode(String responseMode) {

        this.responseMode = responseMode;
    }

    public String getRedirectUrl() {

        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {

        this.redirectUrl = redirectUrl;
    }

    public String getSigningTenantDomain() {

        return signingTenantDomain;
    }

    public void setSigningTenantDomain(String signingTenantDomain) {

        this.signingTenantDomain = signingTenantDomain;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getSessionState() {

        return sessionState;
    }

    public void setSessionState(String sessionState) {

        this.sessionState = sessionState;
    }

    public boolean isError() {

        return errorResponseDTO != null;
    }

    public void setError(int responseCode, String errorMsg, String oauthErrorMessage) {

        successResponseDTO = null;
        this.responseCode = responseCode;
        errorResponseDTO = new ErrorResponseDTO();
        errorResponseDTO.setErrorDescription(errorMsg);
        errorResponseDTO.setError(oauthErrorMessage);
    }

    public String getFormPostRedirectPage() {

        return formPostRedirectPage;
    }

    public void setFormPostRedirectPage(String formPostRedirectPage) {

        this.formPostRedirectPage = formPostRedirectPage;
    }

    public String getAuthenticatedIDPs() {

        return authenticatedIDPs;
    }

    public void setAuthenticatedIDPs(String authenticatedIDPs) {

        this.authenticatedIDPs = authenticatedIDPs;
    }

    public int getResponseCode() {

        return responseCode;
    }

    public void setResponseCode(int responseCode) {

        this.responseCode = responseCode;
    }

    public boolean isMtlsRequest() {

        return isMtlsRequest;
    }

    public void setMtlsRequest(boolean mtlsRequest) {

        isMtlsRequest = mtlsRequest;
    }
}
