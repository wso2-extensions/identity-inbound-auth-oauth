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

package org.wso2.carbon.identity.oauth2.responsemode.provider.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AbstractResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * This class is used when response_mode = query.
 * This class should not be used when response_type has token or id_token
 */
public class QueryResponseModeProvider extends AbstractResponseModeProvider {

    private static final Log log = LogFactory.getLog(QueryResponseModeProvider.class);

    private static final String RESPONSE_MODE = OAuthConstants.ResponseModes.QUERY;
    private static final String FRAGMENT_RESPONSE_MODE = OAuthConstants.ResponseModes.FRAGMENT;

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public boolean canHandle(AuthorizationResponseDTO authorizationResponseDTO) {

        // This ResponseModeProvider cannot handle response types that contain "token" or "ide_token".
        String responseType = authorizationResponseDTO.getResponseType();

        return !hasIDTokenOrTokenInResponseType(responseType) &&
                getResponseMode().equals(authorizationResponseDTO.getResponseMode());
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

        String responseType = authorizationResponseDTO.getResponseType();
        if (hasIDTokenOrTokenInResponseType(responseType)) {
            // When responseType contains "id_token" or "token" the resulting token is passed back as a URI fragment
            // as per the specification:
            // https://openid.net/specs/openid-connect-core-1_0.html#HybridCallback
            // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#OAuth.Post

            ResponseModeProvider newResponseModeProvider =
                    OAuth2ServiceComponentHolder.getResponseModeProvider(FRAGMENT_RESPONSE_MODE);
            return newResponseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO);
        }

        String redirectUrl = authorizationResponseDTO.getRedirectUrl();
        String sessionState = authorizationResponseDTO.getSessionState();
        String state = authorizationResponseDTO.getState();

        if (!authorizationResponseDTO.isError()) {
            String code = authorizationResponseDTO.getSuccessResponseDTO().getAuthorizationCode();
            String idToken = authorizationResponseDTO.getSuccessResponseDTO().getIdToken();
            String accessToken = authorizationResponseDTO.getSuccessResponseDTO().getAccessToken();
            String tokenType = authorizationResponseDTO.getSuccessResponseDTO().getTokenType();
            long validityPeriod = authorizationResponseDTO.getSuccessResponseDTO().getValidityPeriod();
            String scope = authorizationResponseDTO.getSuccessResponseDTO().getScope();
            String authenticatedIdPs = authorizationResponseDTO.getAuthenticatedIDPs();
            String subjectToken = authorizationResponseDTO.getSuccessResponseDTO().getSubjectToken();
            List<String> queryParams = new ArrayList<>();
            if (accessToken != null) {
                appendQueryParam(queryParams, OAuthConstants.ACCESS_TOKEN_RESPONSE_PARAM, accessToken);
                appendQueryParam(queryParams, OAuthConstants.EXPIRES_IN, String.valueOf(validityPeriod));
            }

            if (tokenType != null) {
                appendQueryParam(queryParams, OAuthConstants.TOKEN_TYPE, tokenType);
            }

            if (idToken != null) {
                appendQueryParam(queryParams, OAuthConstants.ID_TOKEN, idToken);
            }

            if (code != null) {
                appendQueryParam(queryParams, OAuthConstants.CODE, code);
            }

            if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
                appendQueryParam(queryParams, OAuthConstants.AUTHENTICATED_IDPS, authenticatedIdPs);
            }

            if (sessionState != null) {
                appendQueryParam(queryParams, OAuthConstants.SESSION_STATE, sessionState);
            }

            if (state != null) {
                appendQueryParam(queryParams, OAuthConstants.STATE, state);
            }

            if (scope != null) {
                appendQueryParam(queryParams, OAuthConstants.SCOPE, scope);
            }

            if (StringUtils.isNotBlank(subjectToken)) {
                appendQueryParam(queryParams, OAuthConstants.SUBJECT_TOKEN, subjectToken);
            }

            redirectUrl = FrameworkUtils.appendQueryParamsStringToUrl(redirectUrl,
                    String.join("&", queryParams));
        } else {
            redirectUrl += "?" +
                    OAuthConstants.OAUTH_ERROR + "=" + authorizationResponseDTO.getErrorResponseDTO().getError() +
                    "&" + OAuthConstants.OAUTH_ERROR_DESCRIPTION + "=" +
                    authorizationResponseDTO.getErrorResponseDTO().getErrorDescription()
                            .replace(" ", "+");

            if (StringUtils.isNotBlank(sessionState)) {
                redirectUrl += "&" + OAuthConstants.SESSION_STATE + "=" + encodeValue(sessionState);
            }

            if (StringUtils.isNotBlank(state)) {
                redirectUrl += "&" + OAuthConstants.STATE + "=" + encodeValue(state);
            }
        }
        authorizationResponseDTO.setRedirectUrl(redirectUrl);
        return redirectUrl;
    }

    @Override
    public String getAuthResponseBuilderEntity(AuthorizationResponseDTO authorizationResponseDTO) {

        return null;
    }

    @Override
    public AuthResponseType getAuthResponseType() {

        return AuthResponseType.REDIRECTION;
    }


    private void appendQueryParam(List<String> queryParams, String key, String value) {

        String encodedValue = encodeValue(value);
        queryParams.add(key + "=" + encodedValue);
    }

    private String encodeValue(String value) {

        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            // This exception will not be thrown as UTF-8 is always supported.
            log.error("Error occurred while encoding the value: " + value, e);
            return null;
        }
    }
}
