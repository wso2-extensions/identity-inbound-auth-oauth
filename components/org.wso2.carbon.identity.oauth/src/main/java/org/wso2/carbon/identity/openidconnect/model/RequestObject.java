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


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
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
    public static final String ESSENTIAL = "essential";
    public static final String VALUE = "value";
    public static final String VALUES = "values";
    private boolean isSignatureValid;

    private SignedJWT signedJWT;
    private PlainJWT plainJWT;
    private JWTClaimsSet claimsSet;

    /**
     * To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or
     * id_token or any custom member. Sample set of values that can be exist in this map is as below.
     * Map<"id_token", ("username, firstname, lastname")>
     */
    private Map<String, List<RequestedClaim>> requestedClaims = new HashMap<>();

    public boolean isSignatureValid() {
        return isSignatureValid;
    }

    public void setIsSignatureValid(boolean isSignatureValid) {
        this.isSignatureValid = isSignatureValid;
    }

    public boolean isSigned() {
        return this.signedJWT != null;
    }

    public PlainJWT getPlainJWT() {
        return plainJWT;
    }

    /**
     * Extract jwtclaimset from plain jwt and extract claimsforClaimRequestor
     *
     * @param plainJWT
     * @throws ParseException
     */
    public void setPlainJWT(PlainJWT plainJWT) throws RequestObjectException {
        this.plainJWT = plainJWT;
        try {
            this.setClaimSet(plainJWT.getJWTClaimsSet());
        } catch (ParseException e) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Unable to parse Claim Set in " +
                    "the Request Object.");
        }
        if (this.claimsSet.getClaim(CLAIMS) != null) {
            JSONObject claims = this.claimsSet.toJSONObject();
            processClaimObject(claims);
        }
    }

    public Map<String, List<RequestedClaim>> getRequestedClaims() {
        return requestedClaims;
    }

    public void setRequestedClaims(Map<String, List<RequestedClaim>> claimsforRequestParameter) {
        this.requestedClaims = claimsforRequestParameter;
    }

    public SignedJWT getSignedJWT() {
        return signedJWT;
    }

    /**
     * Mark the object as signed.
     * Extract jwtclaimset from signed jwt and extract claimsforClaimRequestor
     *
     * @param signedJWT
     * @throws ParseException
     */
    public void setSignedJWT(SignedJWT signedJWT) throws RequestObjectException {
        this.signedJWT = signedJWT;
        try {
            setClaimSet(signedJWT.getJWTClaimsSet());
        } catch (ParseException e) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Unable to parse Claim Set in " +
                    "the Request Object.");
        }
        if (this.claimsSet.getClaim(CLAIMS) != null) {
            JSONObject claims = this.claimsSet.toJSONObject();
            processClaimObject(claims);
        }
    }

    public void setClaimSet(JWTClaimsSet claimSet) {
        this.claimsSet = claimSet;
    }

    public JWTClaimsSet getClaimsSet() {
        return claimsSet;
    }

    /**
     * To process the claim object which comes with the request object.
     *
     * @param jsonObjectRequestedClaims requested claims of the request object
     * @throws ParseException
     */
    private void processClaimObject(JSONObject jsonObjectRequestedClaims) throws RequestObjectException {

        try {
            Map<String, List<RequestedClaim>> claimsforClaimRequestor = new HashMap<>();
            if (jsonObjectRequestedClaims.get(CLAIMS) != null) {
                JSONObject jsonObjectClaim = (JSONObject) jsonObjectRequestedClaims.get(CLAIMS);

                //To iterate the claims json object to fetch the claim requestor and all requested claims.
                for (Map.Entry<String, Object> requesterClaimsMap : jsonObjectClaim.entrySet()) {
                    List<RequestedClaim> requestedClaimsList = new ArrayList();
                    JSONObject jsonObjectAllRequestedClaims;
                    if (jsonObjectClaim.get(requesterClaimsMap.getKey()) != null) {
                        jsonObjectAllRequestedClaims = (JSONObject) jsonObjectClaim.get(requesterClaimsMap.getKey());

                        if (jsonObjectAllRequestedClaims != null) {
                            for (Map.Entry<String, Object> requestedClaims : jsonObjectAllRequestedClaims.entrySet()) {
                                JSONObject jsonObjectClaimAttributes = null;
                                if (jsonObjectAllRequestedClaims.get(requestedClaims.getKey()) != null) {
                                    jsonObjectClaimAttributes = (JSONObject) jsonObjectAllRequestedClaims.get(requestedClaims.getKey());
                                }
                                populateRequestedClaimValues(requestedClaimsList, jsonObjectClaimAttributes,
                                        requestedClaims.getKey(), requesterClaimsMap.getKey());
                            }
                        }
                    }
                    claimsforClaimRequestor.put(requesterClaimsMap.getKey(), requestedClaimsList);
                }
                this.setRequestedClaims(claimsforClaimRequestor);
            }
        } catch (ClassCastException e) {
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, "Requested \"claims\" in Request " +
                    "Object is in invalid format.");
        }
    }

    private void populateRequestedClaimValues(List<RequestedClaim> requestedClaims,
                                              JSONObject jsonObjectClaimAttributes, String claimName, String claimType) {

        RequestedClaim claim = new RequestedClaim();
        claim.setName(claimName);
        claim.setType(claimType);
        if (jsonObjectClaimAttributes != null) {

            //To iterate claim attributes object to fetch the attribute key and value for the fetched
            // requested claim in the fetched claim requester
            for (Map.Entry<String, Object> claimAttributes : jsonObjectClaimAttributes.entrySet()) {
                if (jsonObjectClaimAttributes.get(claimAttributes.getKey()) != null) {
                    Object value = jsonObjectClaimAttributes.get(claimAttributes.getKey());
                    if (ESSENTIAL.equals(claimAttributes.getKey())) {
                        claim.setEssential((Boolean) value);
                    } else if (VALUE.equals(claimAttributes.getKey())) {
                        claim.setValue((String) value);
                    } else if (VALUES.equals(claimAttributes.getKey())) {
                        JSONArray jsonArray = (JSONArray) value;
                        if (jsonArray != null && jsonArray.size() > 0) {
                            List<String> values = new ArrayList<>();
                            for (Object aJsonArray : jsonArray) {
                                values.add(aJsonArray.toString());
                            }
                            claim.setValues(values);
                        }
                    }
                }
                requestedClaims.add(claim);
            }
        } else {
            requestedClaims.add(claim);
        }
    }

    /**
     * Return the String claim value which matches the given claimName, from jwtClaimset
     * return null if not found, or unable to parse
     *
     * @param claimName
     * @return string value of the claim
     */
    public String getClaimValue(String claimName) {
        try {
            return claimsSet.getStringClaim(claimName);
        } catch (ParseException e) {
            return StringUtils.EMPTY;
        }
    }

    /**
     * Return the claim value which matches the given claimName, from jwtClaimset
     *
     * @param claimName
     * @return Claim value object
     */
    public Object getClaim(String claimName) {
        return claimsSet.getClaim(claimName);
    }

}
