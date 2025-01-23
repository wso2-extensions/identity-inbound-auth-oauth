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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AbstractResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * This class is used when response_mode = fragment.
 */
public class FragmentResponseModeProvider extends AbstractResponseModeProvider {

    private static final Log log = LogFactory.getLog(FragmentResponseModeProvider.class);

    private static final String RESPONSE_MODE = OAuthConstants.ResponseModes.FRAGMENT;

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

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
            final AuthorizationDetails authorizationDetails = authorizationResponseDTO.getSuccessResponseDTO()
                    .getAuthorizationDetails();
            List<String> params = new ArrayList<>();
            if (accessToken != null) {
                appendParam(params, OAuthConstants.ACCESS_TOKEN_RESPONSE_PARAM, accessToken);
                appendParam(params, OAuthConstants.EXPIRES_IN, String.valueOf(validityPeriod));
            }

            if (tokenType != null) {
                appendParam(params, OAuthConstants.TOKEN_TYPE, tokenType);
            }

            if (idToken != null) {
                appendParam(params, OAuthConstants.ID_TOKEN, idToken);
            }

            if (code != null) {
                appendParam(params, OAuthConstants.CODE, code);
            }

            if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
                appendParam(params, OAuthConstants.AUTHENTICATED_IDPS, authenticatedIdPs);
            }

            if (sessionState != null) {
                appendParam(params, OAuthConstants.SESSION_STATE, sessionState);
            }

            if (state != null) {
                appendParam(params, OAuthConstants.STATE, state);
            }

            if (scope != null) {
                appendParam(params, OAuthConstants.SCOPE, scope);
            }

            if (StringUtils.isNotBlank(subjectToken)) {
                appendParam(params, OAuthConstants.SUBJECT_TOKEN, subjectToken);
            }

            if (AuthorizationDetailsUtils.isRichAuthorizationRequest(authorizationDetails)) {
                params.add(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS + "=" +
                        AuthorizationDetailsUtils.getUrlEncodedAuthorizationDetails(authorizationDetails));
            }

            redirectUrl += "#" + String.join("&", params);

        } else {
            redirectUrl += "#" +
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

    private void appendParam(List<String> params, String key, String value) {

        String encodedValue = encodeValue(value);
        params.add(key + "=" + encodedValue);
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
