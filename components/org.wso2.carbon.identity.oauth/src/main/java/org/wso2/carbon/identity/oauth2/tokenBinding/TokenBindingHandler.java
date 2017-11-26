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
package org.wso2.carbon.identity.oauth2.tokenBinding;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.xml.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getAppInformationByClientId;

/**
 * This class handles Token Binding For oauth2.0 requests.
 */
public class TokenBindingHandler implements TokenBinding {
    private static Log log = LogFactory.getLog(TokenBindingHandler.class);
    private static String delimiter = "&#%";

    private boolean tBSupportExist = false;

    public void settBSupportEnabled(boolean tBSupportEnabled) {
        this.tBSupportEnabled = tBSupportEnabled;
    }

    private boolean tBSupportEnabled = false;


    public static void setDelimiter(String delimiter) {
        if (!StringUtils.isEmpty(delimiter)) {
            TokenBindingHandler.delimiter = delimiter;
        }
    }

    public boolean istBSupportExist() {
        return tBSupportExist;
    }

    public boolean istBSupportEnabled() {
        return tBSupportEnabled;
    }

    public static String getDelimiter() {
        return delimiter;
    }

    //Token binding for authorization code

    /**
     * Perform PCKE validation for TokenBinding.
     *
     * @param PKCECodeChallenge
     * @param codeVerifier
     * @param oauthorizationCode
     * @return
     */
    @Override
    public boolean validateAuthorizationCode(String PKCECodeChallenge, String codeVerifier, String
            oauthorizationCode) {
        if (codeVerifier == null) {
            return false;
        }
        String authorizationCode = getFirstValue(oauthorizationCode, delimiter);
        if (!authorizationCode.equals(hashOfString(codeVerifier))) {
            if (log.isDebugEnabled()) {
                log.debug("PKCE validation failed due to Token binding Value of Authorization Code is not equal " +
                        "to current token binding value of connection");
            }
            return false;
        }
        return true;
    }

    //for Token Binding for introspection point

    /**
     * Returns the hash value of the token binding.
     * Used to validate access token in introspection point.
     *
     * @param accessTokenDO
     * @return
     */
    @Override
    public String validateAccessToken(AccessTokenDO accessTokenDO) {
        String tbh;
        String accesstoken = accessTokenDO.getAccessToken();
        if (findBase64Encode(accesstoken)) {
            tbh = new String(Base64.decodeBase64(accesstoken), (Charsets.UTF_8));
            if (tbh.contains(":")) {
                tbh = tbh.split(":")[0];
                tbh = new String(Base64.decodeBase64(tbh), (Charsets.UTF_8));
            }
            if (tbh.contains(delimiter))
                tbh = tbh.split(delimiter)[0];
            return tbh;
        }
        return null;
    }

    /**
     * Finds Base64Encode pattern exists in given token
     *
     * @param tokenID
     * @return
     */
    private boolean findBase64Encode(String tokenID) {
        String pattern1 = "^([A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{4}$";
        String pattern2 = "^([A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{3}=$";
        String pattern3 = "^([A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{2}==$";
        if (tokenID.matches(pattern1) || tokenID.matches(pattern2) || tokenID.matches(pattern3)) {
            return true;
        }
        return false;
    }

    //Token binding for access token& refresh token
    /**
     * This method binds the token to token binding ID
     *
     * @param oauthAuthzMsgCtx
     * @param httpTbHeader
     * @param token
     * @return
     */
    @Override
    public String doTokenBinding(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, String httpTbHeader, String token) {
        String tokenBindingId = findTokenBindingHeader(oauthAuthzMsgCtx, httpTbHeader);
        return bindToken(tokenBindingId, token);
    }

    /**
     * This method binds the token to token binding ID.
     *
     * @param tokReqMsgCtx
     * @param httpTbHeader
     * @param token
     * @return
     */
    @Override
    public String doTokenBinding(OAuthTokenReqMessageContext tokReqMsgCtx, String httpTbHeader, String token) {
        String tokenBindingId = findTokenBindingHeader(tokReqMsgCtx, httpTbHeader);
        return bindToken(tokenBindingId, token);
    }

    /**
     * This method binds the token to token binding ID.
     *
     * @param tokenBindingContext
     * @return
     */
    @Override
    public TokenBindingContext doTokenBinding(TokenBindingContext tokenBindingContext) {
        TokenBindingContext bindingContext = tokenBindingContext;
        if (bindingContext.getTokenBindingType() != null && bindingContext.getNormalToken() != null) {
            if (bindingContext.getOauthAuthzMsgCtx() != null) {
                bindingContext.setBoundToken(doTokenBinding(bindingContext.getOauthAuthzMsgCtx(), bindingContext
                        .getTokenBindingType(), bindingContext.getNormalToken()));
                return bindingContext;
            } else if (bindingContext.getTokReqMsgCtx() != null) {
                bindingContext.setBoundToken(doTokenBinding(bindingContext.getTokReqMsgCtx(), bindingContext
                        .getTokenBindingType(), bindingContext.getNormalToken()));
                return bindingContext;
            }
        }
        return tokenBindingContext;
    }

    /**
     * Check whether given refresh token bound to current token binding connection.
     *
     * @param tokReqMsgCtx
     * @return
     */
    @Override
    public boolean validateRefreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) {
        String refreshToken =tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRefreshToken();
        String tokenBindingId = findTokenBindingHeader(tokReqMsgCtx, OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        String tokenHashValue = refreshToken;
        if (OAuth2Util.checkUserNameAssertionEnabled()) {
            tokenHashValue = getFirstValue(tokenHashValue, ":");
        }
        tokenHashValue = getFirstValue(tokenHashValue, delimiter);
        if (!tokenHashValue.equals(hashOfString(tokenBindingId))) {
            return false;
        }
        return true;
    }

    /**
     * Check whether token binding headers exist,if so returns their value.
     *
     * @param httpRequestHeaders
     * @param httpTBheader
     * @return
     */
    public String checkTokenBindingHeader(HttpRequestHeader[] httpRequestHeaders, String httpTBheader) {
        String tokenBindingId = null;
        if (httpRequestHeaders != null) {
            for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
                if (httpRequestHeader.getName().equalsIgnoreCase(httpTBheader)) {
                    tokenBindingId = httpRequestHeader.getValue()[0];
                    if (!StringUtils.isEmpty(tokenBindingId)) {
                        tBSupportExist = true;
                    }
                    break;
                }
            }
        }
        return tokenBindingId;
    }

    /**
     * Find TokenBinding header in request headers.
     *
     * @param oauthAuthzMsgCtx
     * @param httpTBheader
     * @return
     */
    public String findTokenBindingHeader(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, String httpTBheader) {
        HttpRequestHeader[] httpRequestHeaders = oauthAuthzMsgCtx.getAuthorizationReqDTO().getHttpRequestHeaders();
        this.checkTokenBindingSupportEnabled(oauthAuthzMsgCtx);
        return returnTBHeadervalue(httpRequestHeaders, httpTBheader);
    }

    /**
     * Find TokenBinding header in request headers.
     *
     * @param tokReqMsgCtx
     * @param httpTBheader
     * @return
     */
    public String findTokenBindingHeader(OAuthTokenReqMessageContext tokReqMsgCtx, String httpTBheader) {
        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        this.checkTokenBindingSupportEnabled(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
        return returnTBHeadervalue(httpRequestHeaders, httpTBheader);

    }

    //General Token binding support

    /**
     * Check whether user enabled token binding support.
     *
     * @param ClientId
     */
    public void checkTokenBindingSupportEnabled(String ClientId) {
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = getAppInformationByClientId(ClientId);
        } catch (InvalidOAuthClientException e) {
            log.debug("Error while retrieving app information for clientId :"+ClientId);
        } catch (IdentityOAuth2Exception e) {
            log.debug("Error while retrieving app information for clientId :"+ClientId);
        }
        if (oAuthAppDO != null && oAuthAppDO.isTbMandatory()) {
            this.tBSupportEnabled = true;
        }
    }

    /**
     * Check whether user enabled token binding support.
     *
     * @param oauthAuthzMsgCtx
     */
    public void checkTokenBindingSupportEnabled(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey());
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            log.debug("Error while retrieving app information for ConsumerKey :"+oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey());
        }
        if (oAuthAppDO != null && oAuthAppDO.isTbMandatory()) {
            this.tBSupportEnabled = true;
        }
    }

    /**
     * Use to hash token binding ID. Hashing algorithm is SHA-256.
     *
     * @param tokenBindingID
     * @return
     */
    private String hashOfString(String tokenBindingID) {
        String hashValue = "";
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(tokenBindingID.getBytes(StandardCharsets.US_ASCII));
            //Trim the base64 string to remove trailing CR LF characters.
            hashValue = new String(Base64.encodeBase64URLSafe(hash),
                    StandardCharsets.UTF_8).trim();
        } catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithmException while calculating SHA-256 of " + tokenBindingID + ".");
            if (log.isDebugEnabled()) {
                log.debug("Failed to create SHA256 Message Digest.");
            }
        }
        return hashValue;
    }

    /**
     * Decode base64 encoding and split it to get the first value.
     *
     * @param base64encode
     * @param delimiter
     * @return
     */
    private String getFirstValue(String base64encode, String delimiter) {
        return (new String(Base64.decodeBase64(base64encode), (Charsets.UTF_8))).split(delimiter)[0];
    }

    /**
     * If token binding headers exists and token binding option is enabled returns token binding id.
     *
     * @param httpRequestHeaders
     * @param httpTBheader
     * @return
     */
    private String returnTBHeadervalue(HttpRequestHeader[] httpRequestHeaders, String httpTBheader) {
        String tokenBindingId = checkTokenBindingHeader(httpRequestHeaders, httpTBheader);
        if (tBSupportExist) {
            if (!tBSupportEnabled) {
                return null;
            }
        }
        return tokenBindingId;
    }

    /**
     * Binds token binding Id and normal token using delimiter and encode it in Base64.
     *
     * @param tokenBindingID
     * @param token
     * @return
     */
    private String bindToken(String tokenBindingID, String token) {
        if (!StringUtils.isEmpty(tokenBindingID)) {
            String newToken = hashOfString(tokenBindingID) + delimiter + token;
            String encodedToken = new String(Base64.encodeBase64(newToken.getBytes(Charsets.UTF_8)));
            return encodedToken;
        }
        return token;
    }

}
