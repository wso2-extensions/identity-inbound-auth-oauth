/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.openidconnect.model;


import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *  This class is used to model the request object which comes as a parameter of the OIDC authorization request
 *
 */
public class RequestObject implements Serializable {

    private static final long serialVersionUID = 7180827153818376043L;

    private String clientId;
    private String redirectUri;
    private String[] scopes;
    private String state;
    private String nonce;
    private String iss;
    private String aud;
    private String responseType;
    private long maxAge;
    private boolean isSignatureValid = true;
    private boolean isValidRequestURI = true;
    // This is used for extensions.
    private Map<String, Object> properties = new HashMap<String, Object>();

    //To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or id token
    // or any custom member. Sample set of values that can be exist in this map is as below.
    //Map<"id_token", ("username, firstname, lastname")>
    private Map<String, List<Claim>> claimsforRequestParameter = new HashMap<>();

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String[] getScopes() {
        return scopes;
    }

    public void setScopes(String[] scopes) {
        this.scopes = scopes;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public long getMaxAge() {
        return maxAge;
    }

    public void setMaxAge(long maxAge) {
        this.maxAge = maxAge;
    }

    public boolean isSignatureValid() {
        return isSignatureValid;
    }

    public boolean isValidRequestURI() {
        return isValidRequestURI;
    }

    public void setIsValidRequestURI(boolean isValidRequestURI) {
        this.isValidRequestURI = isValidRequestURI;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
    }

    public Map<String, List<Claim>> getClaimsforRequestParameter() {
        return claimsforRequestParameter;
    }

    public void setClaimsforRequestParameter(Map<String, List<Claim>> claimsforRequestParameter) {
        this.claimsforRequestParameter = claimsforRequestParameter;
    }
}
