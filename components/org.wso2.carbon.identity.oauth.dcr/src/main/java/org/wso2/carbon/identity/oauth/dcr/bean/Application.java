/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dcr.bean;

import java.io.Serializable;
import java.util.List;

/**
 * This object contains the context related to OAuth application.
 */
public class Application implements Serializable {

    private static final long serialVersionUID = -4515815791420125411L;

    private String clientName = null;
    private String clientId = null;
    private String clientSecret = null;
    private List<String> redirectUris = null;
    private List<String> grantTypes = null;
    private String jwksURI = null;
    private String tokenEndpointAuthMethod = null;
    private String tokenEndpointAuthSignatureAlgorithm = null;
    private String sectorIdentifierURI = null;
    private String idTokenSignatureAlgorithm = null;
    private String requestObjectSignatureAlgorithm = null;
    private String tlsClientAuthSubjectDN = null;
    private boolean requirePushedAuthorizationRequests;
    private boolean tlsClientCertificateBoundAccessTokens;
    private String subjectType = null;
    private String requestObjectEncryptionAlgorithm = null;
    private String requestObjectEncryptionMethod = null;
    private boolean isRequestObjectSignatureValidationEnabled;
    private String idTokenEncryptionAlgorithm = null;
    private String idTokenEncryptionMethod = null;
    private String softwareStatement = null;

    public String getSoftwareStatement() {

        return softwareStatement;
    }

    public void setSoftwareStatement(String softwareStatement) {

        this.softwareStatement = softwareStatement;
    }

    public String getClientName() {

        return clientName;
    }

    public void setClientName(String clientName) {

        this.clientName = clientName;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getClientSecret() {

        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {

        this.clientSecret = clientSecret;
    }

    public List<String> getRedirectUris() {

        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {

        this.redirectUris = redirectUris;
    }

    public List<String> getGrantTypes() {

        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {

        this.grantTypes = grantTypes;
    }
    public String getJwksURI() {

        return jwksURI;
    }

    public void setJwksURI(String jwksURI) {

        this.jwksURI = jwksURI;
    }

    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {

        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getTokenEndpointAuthSignatureAlgorithm() {

        return tokenEndpointAuthSignatureAlgorithm;
    }

    public void setTokenEndpointAuthSignatureAlgorithm(String tokenEndpointAuthSignatureAlgorithm) {

        this.tokenEndpointAuthSignatureAlgorithm = tokenEndpointAuthSignatureAlgorithm;
    }

    public String getSectorIdentifierURI() {

        return sectorIdentifierURI;
    }

    public void setSectorIdentifierURI(String sectorIdentifierURI) {

        this.sectorIdentifierURI = sectorIdentifierURI;
    }

    public String getIdTokenSignatureAlgorithm() {

        return idTokenSignatureAlgorithm;
    }

    public void setIdTokenSignatureAlgorithm(String idTokenSignatureAlgorithm) {

        this.idTokenSignatureAlgorithm = idTokenSignatureAlgorithm;
    }
    public String getRequestObjectSignatureAlgorithm() {

        return requestObjectSignatureAlgorithm;
    }

    public void setRequestObjectSignatureAlgorithm(String requestObjectSignatureAlgorithm) {

        this.requestObjectSignatureAlgorithm = requestObjectSignatureAlgorithm;
    }

    public String getTlsClientAuthSubjectDN() {

        return tlsClientAuthSubjectDN;
    }

    public void setTlsClientAuthSubjectDN(String tlsClientAuthSubjectDN) {

        this.tlsClientAuthSubjectDN = tlsClientAuthSubjectDN;
    }

    public boolean isRequirePushedAuthorizationRequests() {

        return requirePushedAuthorizationRequests;
    }

    public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {

        this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
    }

    public boolean isTlsClientCertificateBoundAccessTokens() {

        return tlsClientCertificateBoundAccessTokens;
    }

    public void setTlsClientCertificateBoundAccessTokens(boolean tlsClientCertificateBoundAccessTokens) {

        this.tlsClientCertificateBoundAccessTokens = tlsClientCertificateBoundAccessTokens;
    }

    public String getSubjectType() {

        return subjectType;
    }

    public void setSubjectType(String subjectType) {

        this.subjectType = subjectType;
    }

    public String getRequestObjectEncryptionAlgorithm() {

        return requestObjectEncryptionAlgorithm;
    }

    public void setRequestObjectEncryptionAlgorithm(String requestObjectEncryptionAlgorithm) {

        this.requestObjectEncryptionAlgorithm = requestObjectEncryptionAlgorithm;
    }

    public String getRequestObjectEncryptionMethod() {

        return requestObjectEncryptionMethod;
    }

    public void setRequestObjectEncryptionMethod(String requestObjectEncryptionMethod) {

        this.requestObjectEncryptionMethod = requestObjectEncryptionMethod;
    }

    public boolean isRequestObjectSignatureValidationEnabled() {

        return isRequestObjectSignatureValidationEnabled;
    }

    public void setRequestObjectSignatureValidationEnabled(boolean requestObjectSignatureValidationEnabled) {

        isRequestObjectSignatureValidationEnabled = requestObjectSignatureValidationEnabled;
    }

    public String getIdTokenEncryptionAlgorithm() {

        return idTokenEncryptionAlgorithm;
    }

    public void setIdTokenEncryptionAlgorithm(String idTokenEncryptionAlgorithm) {

        this.idTokenEncryptionAlgorithm = idTokenEncryptionAlgorithm;
    }

    public String getIdTokenEncryptionMethod() {

        return idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionMethod(String idTokenEncryptionMethod) {

        this.idTokenEncryptionMethod = idTokenEncryptionMethod;
    }
    @Override
    public String toString() {

        return "Application {\n" +
                "  clientName: " + this.clientName + "\n" +
                "  clientId: " + this.clientId + "\n" +
                "  clientSecret: " + this.clientSecret + "\n" +
                "  redirectUris: " + this.redirectUris + "\n" +
                "  grantTypes: " + this.grantTypes + "\n" +
                "}\n";
    }
}
