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
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AbstractResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;

/**
 * This class is used when response_mode = form_post.
 */
public class FormPostResponseModeProvider extends AbstractResponseModeProvider {

    private static final String RESPONSE_MODE = OAuthConstants.ResponseModes.FORM_POST;

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public String getAuthResponseBuilderEntity(AuthorizationResponseDTO authorizationResponseDTO) {

        String params;
        if (authorizationResponseDTO.isError()) {
            params = buildErrorParams(authorizationResponseDTO);
        } else {
            params = buildParams(authorizationResponseDTO.getSuccessResponseDTO().getFormPostBody(),
                    authorizationResponseDTO.getAuthenticatedIDPs(),
                    authorizationResponseDTO.getSessionState(), authorizationResponseDTO.getState());
        }
        String htmlForm = createBaseFormPage(params, authorizationResponseDTO.getRedirectUrl(),
                authorizationResponseDTO.getFormPostRedirectPage());
        authorizationResponseDTO.setRedirectUrl(htmlForm);
        return htmlForm;
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

        return null;
    }

    @Override
    public AuthResponseType getAuthResponseType() {

        return AuthResponseType.POST_RESPONSE;
    }

    private String buildParams(String jsonPayLoad, String authenticatedIdPs, String sessionStateValue, String state) {

        JSONObject jsonObject = new JSONObject(jsonPayLoad);
        StringBuilder paramStringBuilder = new StringBuilder();

        for (Object key : jsonObject.keySet()) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"")
                    .append(key)
                    .append("\"" + "value=\"")
                    .append(Encode.forHtml(jsonObject.get(key.toString()).toString()))
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(authenticatedIdPs) && !jsonObject.has(OAuthConstants.AUTHENTICATED_IDPS)) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"AuthenticatedIdPs\" value=\"")
                    .append(authenticatedIdPs)
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(sessionStateValue) && !jsonObject.has(OAuthConstants.SESSION_STATE)) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"session_state\" value=\"")
                    .append(sessionStateValue)
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(state) && !jsonObject.has(OAuthConstants.STATE)) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"state\" value=\"")
                    .append(state)
                    .append("\"/>\n");
        }
        return paramStringBuilder.toString();
    }

    private String buildErrorParams(AuthorizationResponseDTO authorizationResponseDTO) {

        StringBuilder paramStringBuilder = new StringBuilder();

        if (StringUtils.isNotEmpty(authorizationResponseDTO.getErrorResponseDTO()
                .getError())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"error\" value=\"")
                    .append(authorizationResponseDTO.getErrorResponseDTO().getError())
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(authorizationResponseDTO.getErrorResponseDTO().getErrorDescription())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"error_description\" value=\"")
                    .append(authorizationResponseDTO.getErrorResponseDTO().getErrorDescription())
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(authorizationResponseDTO.getSessionState())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"session_state\" value=\"")
                    .append(authorizationResponseDTO.getSessionState())
                    .append("\"/>\n");
        }

        if (StringUtils.isNotEmpty(authorizationResponseDTO.getState())) {
            paramStringBuilder.append("<input type=\"hidden\" name=\"state\" value=\"")
                    .append(authorizationResponseDTO.getState())
                    .append("\"/>\n");
        }

        return paramStringBuilder.toString();
    }

    private String createBaseFormPage(String params, String redirectURI, String formPostRedirectPage) {

        if (StringUtils.isNotBlank(formPostRedirectPage)) {
            String pageWithRedirectURI = formPostRedirectPage.replace("$redirectURI", redirectURI);
            return pageWithRedirectURI.replace("<!--$params-->", params);
        }

        String formHead = "<html>\n" +
                "   <head><title>Submit This Form</title></head>\n" +
                "   <body onload=\"javascript:document.forms[0].submit()\">\n" +
                "    <p>Click the submit button if automatic redirection failed.</p>" +
                "    <form method=\"post\" action=\"" + redirectURI + "\">\n";

        String formBottom = "<input type=\"submit\" value=\"Submit\">" +
                "</form>\n" +
                "</body>\n" +
                "</html>";

        String form = formHead + params +
                formBottom;
        return form;
    }
}
