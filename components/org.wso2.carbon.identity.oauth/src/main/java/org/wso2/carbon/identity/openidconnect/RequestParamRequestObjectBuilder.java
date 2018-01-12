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
package org.wso2.carbon.identity.openidconnect;

import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.openidconnect.model.Claim;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * This class is used to build request object parameter value which comes with the OIDC authorization request as an optional
 * parameter
 */
public class RequestParamRequestObjectBuilder implements RequestObjectBuilder {

    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String SCOPE = "scope";
    private static final String STATE = "state";
    private static final String NONCE = "nonce";
    private static final String ISS = "iss";
    private static final String AUD = "aud";
    private static final String RESPONSE_TYPE = "response_type";
    private static final String MAX_AGE = "max_age";
    private static String CLAIMS = "claims";
    private static final Base64 base64Url = new Base64(true);
    //To store the claims requestor and the the requested claim list. claim requestor can be either userinfo or idtoken
    // or any custom member.
    private static Map<String, List<Claim>> claimsforClaimRequestor = new HashMap<>();
    private static Log log = LogFactory.getLog(RequestParamRequestObjectBuilder.class);

    /**
     * Builds request object which comes as the value of the request query parameter of OIDC authorization request
     *
     * @param requestObjectParamValue request object
     * @throws RequestObjectException
     */
    @Override
    public void buildRequestObject(String requestObjectParamValue, OAuth2Parameters oAuth2Parameters,
                                   RequestObject requestObjectInstance) throws RequestObjectException {

        RequestObjectValidator requestObjectValidator = OAuthServerConfiguration.getInstance()
                .getRequestObjectValidator();
        if (requestObjectValidator.isEncrypted(requestObjectParamValue)){
            requestObjectParamValue = requestObjectValidator.decrypt(requestObjectParamValue, oAuth2Parameters);
        }

        SignedJWT signedJWT = getSignedJWT(requestObjectParamValue);
        if (signedJWT!= null) {
            requestObjectInstance.setSignedJWT(signedJWT);
        } else {
            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST,
                    "Unable to build a valid Request Object from the request.");
        }
    }


    private SignedJWT getSignedJWT(String requestObjectString) throws RequestObjectException {
        SignedJWT signedJWT;
        if (isEmpty(requestObjectString)) {
            return null;
        }
        try {
            signedJWT = SignedJWT.parse(requestObjectString);
        } catch (java.text.ParseException e) {
            String errorMessage = "Error while parsing the Request Object JWT.";
            log.error(errorMessage, e);
            throw new RequestObjectException(OAuth2ErrorCodes.SERVER_ERROR, errorMessage);
        }
        if (signedJWT == null) {
            String errorMessage = "No Valid Request Object is found in request.";
            log.error(errorMessage);
            throw new RequestObjectException(OAuth2ErrorCodes.INVALID_REQUEST, errorMessage);
        }
        return signedJWT;
    }

//    private void processClaims(JSONObject jsonObjectRequestedClaims, RequestObject requestObjectInstance)
//            throws RequestObjectException {
//
//        //To process the basic claims which comes with the request parameter.
//        processBasicClaims(jsonObjectRequestedClaims, requestObjectInstance);
//        try {
//            //To process the claim object which comes with the request parameter.
//            processClaimObject(jsonObjectRequestedClaims, requestObjectInstance);
//        } catch (ParseException e) {
//            throw new RequestObjectException(RequestObjectException.ERROR_CODE_INVALID_REQUEST, "Error occured while " +
//                    "processing the request parameter value json object.");
//        }
//    }

//    /**
//     * To process the basic claims as client_id ,redirect_url with in the request object.
//     *
//     * @param jsonObjectRequestedClaims requested claims from the json object
//     * @param requestObjectInstance     instance of request object
//     */
//    private void processBasicClaims(JSONObject jsonObjectRequestedClaims, RequestObject requestObjectInstance) {
//
//        if (jsonObjectRequestedClaims.get(CLIENT_ID) != null) {
//            requestObjectInstance.setClientId(jsonObjectRequestedClaims.get(CLIENT_ID).toString());
//        }
//        if (jsonObjectRequestedClaims.get(REDIRECT_URI) != null) {
//            requestObjectInstance.setRedirectUri(jsonObjectRequestedClaims.get(REDIRECT_URI).toString());
//        }
//        if (jsonObjectRequestedClaims.get(SCOPE) != null) {
//            requestObjectInstance.setScopes(jsonObjectRequestedClaims.get(SCOPE).toString().split(" "));
//        }
//        if (jsonObjectRequestedClaims.get(STATE) != null) {
//            requestObjectInstance.setState(jsonObjectRequestedClaims.get(STATE).toString());
//        }
//        if (jsonObjectRequestedClaims.get(NONCE) != null) {
//            requestObjectInstance.setNonce(jsonObjectRequestedClaims.get(NONCE).toString());
//        }
//        if (jsonObjectRequestedClaims.get(ISS) != null) {
//            requestObjectInstance.setIss(jsonObjectRequestedClaims.get(ISS).toString());
//        }
//        if (jsonObjectRequestedClaims.get(AUD) != null) {
//            requestObjectInstance.setAud(jsonObjectRequestedClaims.get(AUD).toString());
//        }
//        if (jsonObjectRequestedClaims.get(RESPONSE_TYPE) != null) {
//            requestObjectInstance.setResponseType(jsonObjectRequestedClaims.get(RESPONSE_TYPE).toString());
//        }
//        if (jsonObjectRequestedClaims.get(MAX_AGE) != null) {
//            Object maxAge = jsonObjectRequestedClaims.get(MAX_AGE);
//            requestObjectInstance.setMaxAge(new Long(maxAge.toString()));
//        }
//    }

//    /**
//     * To process the claim object which comes with the request object.
//     *
//     * @param jsonObjectRequestedClaims requested claims of the request object
//     * @throws ParseException
//     */
//    private void processClaimObject(JSONObject jsonObjectRequestedClaims, RequestObject requestObjectInstance)
//            throws ParseException {
//
//        if (jsonObjectRequestedClaims.get(CLAIMS) != null) {
//            String allRequestedClaims = null;
//            String claimAttributeValue = null;
//            JSONParser parser = new JSONParser();
//            JSONObject jsonObjectClaim = (JSONObject) parser.parse(jsonObjectRequestedClaims.get(CLAIMS).
//                    toString());
//            //To iterate the claims json object to fetch the claim requestor and all requested claims.
//
//            for (Map.Entry<String, Object> requesterClaimMap : jsonObjectClaim.entrySet()) {
//                List<Claim> essentialClaimsRequestParam = new ArrayList();
//                if (jsonObjectClaim.get(requesterClaimMap.getKey()) != null) {
//                    allRequestedClaims = jsonObjectClaim.get(requesterClaimMap.getKey()).toString();
//                }
//                if (log.isDebugEnabled()) {
//                    log.debug("The " + requesterClaimMap.getKey() + " requests " + allRequestedClaims + " set of claims.");
//                }
//                JSONObject jsonObjectAllRequestedClaims = (JSONObject) parser.parse(allRequestedClaims);
//
//                //To iterate all requested claims object to fetch the claim attributes and values for the fetched claim
//                // requestor.
//                for (Map.Entry<String, Object> requestedClaims : jsonObjectAllRequestedClaims.entrySet()) {
//                    JSONObject jsonObjectClaimAttributes = null;
//                    if (jsonObjectAllRequestedClaims.get(requestedClaims.getKey()) != null) {
//                        jsonObjectClaimAttributes = (JSONObject) parser.parse(jsonObjectAllRequestedClaims.get
//                                (requestedClaims.getKey()).toString());
//                    }
//                    if (log.isDebugEnabled()) {
//                        log.debug("The attributes " + jsonObjectAllRequestedClaims + "for the requested claim: " +
//                                requestedClaims.getKey());
//                    }
//                    //To maintain a claim - claim attribute mapping.
//                    addClaimAttributes(claimAttributeValue, essentialClaimsRequestParam, jsonObjectClaimAttributes,
//                            requestedClaims.getKey());
//                }
//                claimsforClaimRequestor.put(requesterClaimMap.getKey(), essentialClaimsRequestParam);
//            }
//            requestObjectInstance.setClaimsforRequestParameter(claimsforClaimRequestor);
//        }
//    }

//    private void addClaimAttributes(String claimAttributeValue, List<Claim> essentialClaimsRequestParam,
//                                    JSONObject jsonObjectClaimAttributes, String claimName) {
//
//        Claim claim = new Claim();
//        claim.setName(claimName);
//        if (jsonObjectClaimAttributes != null) {
//
//            //To iterate claim attributes object to fetch the attribute key and value for the fetched
//            // requested claim in the fetched claim requestor
//            for (Map.Entry<String, Object> claimAttributes : jsonObjectClaimAttributes.entrySet()) {
//                Map<String, String> claimAttributesMap = new HashMap<>();
//                if (jsonObjectClaimAttributes.get(claimAttributes.getKey()) != null) {
//                    claimAttributeValue = jsonObjectClaimAttributes.get(claimAttributes.getKey()).toString();
//                }
//                claimAttributesMap.put(claimAttributes.getKey(), claimAttributeValue);
//                claim.setClaimAttributesMap(claimAttributesMap);
//                essentialClaimsRequestParam.add(claim);
//            }
//        } else {
//            claim.setClaimAttributesMap(MapUtils.EMPTY_MAP);
//            essentialClaimsRequestParam.add(claim);
//        }
//    }
}
