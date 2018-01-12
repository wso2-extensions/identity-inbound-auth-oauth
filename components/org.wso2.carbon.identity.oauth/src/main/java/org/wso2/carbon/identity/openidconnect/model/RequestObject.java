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


import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.collections.MapUtils;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.RequestObjectException;

import java.io.Serializable;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is used to model the request object which comes as a parameter of the OIDC authorization request
 */
public class RequestObject implements Serializable {

    private static final long serialVersionUID = 7180827153818376043L;
    public static final String CLAIMS = "claims";
    public static final String USERINFO = "userinfo";
    public static final String ID_TOKEN = "id_token";

    private String clientId;
    private String redirectUri;
    private String[] scopes;
    private String state;
    private String nonce;
    private String iss;
    private String aud;
    private String responseType;
    private long maxAge;
    private boolean isSignatureValid;
    private boolean isSigned;
    private String signatureAlgorythm;
    private boolean isValidRequestURI = true;
    // This is used for extensions.
    private Map<String, Object> properties = new HashMap<String, Object>();

    private SignedJWT signedJWT;
    ReadOnlyJWTClaimsSet claimsSet;

    //    //To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or id token
//    // or any custom member. Sample set of values that can be exist in this map is as below.
//    //Map<"id_token", ("username, firstname, lastname")>
    private Map<String, List<Claim>> claimsforRequestParameter = new HashMap<>();

    //
//    public String getState() {
//        return state;
//    }
//
//    public void setState(String state) {
//        this.state = state;
//    }
//
//    public String getClientId() {
//        return clientId;
//    }
//
//    public void setClientId(String clientId) {
//        this.clientId = clientId;
//    }
//
//    public String getRedirectUri() {
//        return redirectUri;
//    }
//
//    public void setRedirectUri(String redirectUri) {
//        this.redirectUri = redirectUri;
//    }
//
//    public String[] getScopes() {
//        return scopes;
//    }
//
//    public void setScopes(String[] scopes) {
//        this.scopes = scopes;
//    }
//
//    public String getNonce() {
//        return nonce;
//    }
//
//    public void setNonce(String nonce) {
//        this.nonce = nonce;
//    }
//
//    public String getIss() {
//        return iss;
//    }
//
//    public void setIss(String iss) {
//        this.iss = iss;
//    }
//
//    public String getAud() {
//        return aud;
//    }
//
//    public void setAud(String aud) {
//        this.aud = aud;
//    }
//
//    public String getResponseType() {
//        return responseType;
//    }
//
//    public void setResponseType(String responseType) {
//        this.responseType = responseType;
//    }
//
//    public long getMaxAge() {
//        return maxAge;
//    }
//
//    public void setMaxAge(long maxAge) {
//        this.maxAge = maxAge;
//    }
//
    public boolean isSignatureValid() {
        return isSignatureValid;
    }

    public void setIsSignatureValid(boolean isSignatureValid) {
        this.isSignatureValid = isSignatureValid;
    }

    public boolean isSigned() {
        return isSigned;
    }

    public void setSigned(boolean isSigned) {
        this.isSigned = isSigned;
    }

    public String getSignatureAlgorythm() {
        return signatureAlgorythm;
    }

    public void setSignatureAlgorythm(String signatureAlgorythm) {
        this.signatureAlgorythm = signatureAlgorythm;
    }

    //
//    public boolean isValidRequestURI() {
//        return isValidRequestURI;
//    }
//
//    public void setIsValidRequestURI(boolean isValidRequestURI) {
//        this.isValidRequestURI = isValidRequestURI;
//    }
//
//    public Map<String, Object> getProperties() {
//        return properties;
//    }
//
//    public void setProperties(Map<String, Object> properties) {
//        this.properties = properties;
//    }
//
    public Map<String, List<Claim>> getClaimsforRequestParameter() {
        return claimsforRequestParameter;
    }

    public void setClaimsforRequestParameter(Map<String, List<Claim>> claimsforRequestParameter) {
        this.claimsforRequestParameter = claimsforRequestParameter;
    }

    public SignedJWT getSignedJWT() {
        return signedJWT;
    }

    public void setSignedJWT(SignedJWT signedJWT) throws RequestObjectException {
        this.signedJWT = signedJWT;
        setClaimSet(signedJWT);
        if (this.claimsSet.getClaim(CLAIMS) != null) {
            net.minidev.json.JSONObject claims = this.claimsSet.toJSONObject();
            processClaimObject(claims);
        }
    }

    /**
     * To process the claim object which comes with the request object.
     *
     * @param jsonObjectRequestedClaims requested claims of the request object
     * @throws ParseException
     */
    private void processClaimObject(net.minidev.json.JSONObject jsonObjectRequestedClaims) {

        Map<String, List<Claim>> claimsforClaimRequestor = new HashMap<>();
        if (jsonObjectRequestedClaims.get(CLAIMS) != null) {
            String claimAttributeValue = null;
            JSONObject jsonObjectClaim = (JSONObject) jsonObjectRequestedClaims.get(CLAIMS);
            //To iterate the claims json object to fetch the claim requestor and all requested claims.

            for (Map.Entry<String, Object> requesterClaimMap : jsonObjectClaim.entrySet()) {
                List<Claim> essentialClaimsRequestParam = new ArrayList();
                JSONObject jsonObjectAllRequestedClaims;
                if (jsonObjectClaim.get(requesterClaimMap.getKey()) != null) {
                    jsonObjectAllRequestedClaims = (JSONObject) jsonObjectClaim.get(requesterClaimMap.getKey());

                    for (Map.Entry<String, Object> requestedClaims : jsonObjectAllRequestedClaims.entrySet()) {
                        JSONObject jsonObjectClaimAttributes = null;
                        if (jsonObjectAllRequestedClaims.get(requestedClaims.getKey()) != null) {
                            jsonObjectClaimAttributes = (JSONObject) jsonObjectAllRequestedClaims.get(requestedClaims.getKey());
                        }
                        addClaimAttributes(claimAttributeValue, essentialClaimsRequestParam, jsonObjectClaimAttributes,
                                requestedClaims.getKey());
                    }
                }
                claimsforClaimRequestor.put(requesterClaimMap.getKey(), essentialClaimsRequestParam);
            }
            this.setClaimsforRequestParameter(claimsforClaimRequestor);
        }
    }

    private void addClaimAttributes(String claimAttributeValue, List<Claim> essentialClaimsRequestParam,
                                    JSONObject jsonObjectClaimAttributes, String claimName) {

        Claim claim = new Claim();
        claim.setName(claimName);
        if (jsonObjectClaimAttributes != null) {

            //To iterate claim attributes object to fetch the attribute key and value for the fetched
            // requested claim in the fetched claim requestor
            for (Map.Entry<String, Object> claimAttributes : jsonObjectClaimAttributes.entrySet()) {
                Map<String, String> claimAttributesMap = new HashMap<>();
                if (jsonObjectClaimAttributes.get(claimAttributes.getKey()) != null) {
                    claimAttributeValue = jsonObjectClaimAttributes.get(claimAttributes.getKey()).toString();
                }
                claimAttributesMap.put(claimAttributes.getKey(), claimAttributeValue);
                claim.setClaimAttributesMap(claimAttributesMap);
                essentialClaimsRequestParam.add(claim);
            }
        } else {
            claim.setClaimAttributesMap(MapUtils.EMPTY_MAP);
            essentialClaimsRequestParam.add(claim);
        }
    }

    private void setClaimSet(SignedJWT signedJWT) throws RequestObjectException {

        try {
            this.claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            String errorMsg = "Error when trying to retrieve claimsSet from the JWT.";
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, errorMsg);
        }
    }

    public ReadOnlyJWTClaimsSet getClaimsSet() {
        return claimsSet;
    }

    public String getClaimValue(String claimName) {
        try {
            return claimsSet.getStringClaim(claimName);
        } catch (ParseException e) {
            return null;
        }
    }

    public Object getClaim(String claimName) {
        return claimsSet.getClaim(claimName);
    }

}
