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


import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.collections.MapUtils;

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
    private boolean isSignatureValid;
    private boolean isSigned;
    private String signatureAlgorythm;

    private SignedJWT signedJWT;
    private PlainJWT plainJWT;
    ReadOnlyJWTClaimsSet claimsSet;
    ReadOnlyJWSHeader jwsHeader;

    /**To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or
     * id_token or any custom member. Sample set of values that can be exist in this map is as below.
     * Map<"id_token", ("username, firstname, lastname")>
     **/
    private Map<String, List<Claim>> claimsforRequestParameter = new HashMap<>();

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

    public PlainJWT getPlainJWT() {
        return plainJWT;
    }

    /**
     * Extract jwtclaimset from plain jwt and extract claimsforClaimRequestor
     * @param plainJWT
     * @throws ParseException
     */
    public void setPlainJWT(PlainJWT plainJWT) throws ParseException {
        this.plainJWT = plainJWT;
        this.setClaimSet(plainJWT.getJWTClaimsSet());
        if (this.claimsSet.getClaim(CLAIMS) != null) {
            net.minidev.json.JSONObject claims = this.claimsSet.toJSONObject();
            processClaimObject(claims);
        }
    }

    public ReadOnlyJWSHeader getJwsHeader() {
        return jwsHeader;
    }

    public String getSignatureAlgorythm() {
        return signatureAlgorythm;
    }

    public void setSignatureAlgorythm(String signatureAlgorythm) {
        this.signatureAlgorythm = signatureAlgorythm;
    }

    public Map<String, List<Claim>> getClaimsforRequestParameter() {
        return claimsforRequestParameter;
    }

    public void setClaimsforRequestParameter(Map<String, List<Claim>> claimsforRequestParameter) {
        this.claimsforRequestParameter = claimsforRequestParameter;
    }

    public SignedJWT getSignedJWT() {
        return signedJWT;
    }

    /**
     * Mark the object as signed.
     * Extract jwtclaimset from signed jwt and extract claimsforClaimRequestor
     * @param signedJWT
     * @throws ParseException
     */
    public void setSignedJWT(SignedJWT signedJWT) throws ParseException {
        this.signedJWT = signedJWT;
        this.setSigned(true);
        setClaimSet(signedJWT.getJWTClaimsSet());
        if (this.claimsSet.getClaim(CLAIMS) != null) {
            net.minidev.json.JSONObject claims = this.claimsSet.toJSONObject();
            processClaimObject(claims);
        }
    }

    public void setClaimSet(ReadOnlyJWTClaimsSet claimSet) {
        this.claimsSet = claimSet;
    }

    public ReadOnlyJWTClaimsSet getClaimsSet() {
        return claimsSet;
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
//            String claimAttributeValue = null;
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
                        addClaimAttributes(essentialClaimsRequestParam, jsonObjectClaimAttributes,
                                requestedClaims.getKey());
                    }
                }
                claimsforClaimRequestor.put(requesterClaimMap.getKey(), essentialClaimsRequestParam);
            }
            this.setClaimsforRequestParameter(claimsforClaimRequestor);
        }
    }

    private void addClaimAttributes(List<Claim> essentialClaimsRequestParam,
                                    JSONObject jsonObjectClaimAttributes, String claimName) {

        Claim claim = new Claim();
        claim.setName(claimName);
        if (jsonObjectClaimAttributes != null) {

            //To iterate claim attributes object to fetch the attribute key and value for the fetched
            // requested claim in the fetched claim requester

            JSONObject claimAttributeValue = null;
            for (Map.Entry<String, Object> claimAttributes : jsonObjectClaimAttributes.entrySet()) {
                Map<String, JSONObject> claimAttributesMap = new HashMap<>();
                if (jsonObjectClaimAttributes.get(claimAttributes.getKey()) != null) {
                    claimAttributeValue = (JSONObject) jsonObjectClaimAttributes.get(claimAttributes.getKey());
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

    /**
     * Return the String claim value which matches the given claimName, from jwtClaimset
     * return null if not found, or unable to parse
     * @param claimName
     * @return
     */
    public String getClaimValue(String claimName) {
        try {
            return claimsSet.getStringClaim(claimName);
        } catch (ParseException e) {
            return null;
        }
    }

    /**
     * Return the claim value which matches the given claimName, from jwtClaimset
     * @param claimName
     * @return
     */
    public Object getClaim(String claimName) {
        return claimsSet.getClaim(claimName);
    }

}
