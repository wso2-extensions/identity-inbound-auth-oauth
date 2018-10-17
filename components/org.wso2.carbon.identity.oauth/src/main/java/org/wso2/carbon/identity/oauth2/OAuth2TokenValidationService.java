/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.TokenValidationHandler;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.triggerOnIntrospectionExceptionListeners;

/**
 * This is the SOAP version of the OAuth validation service which will be used by the resource server.
 */
public class OAuth2TokenValidationService extends AbstractAdmin {

    private static Log log = LogFactory.getLog(OAuth2TokenValidationService.class);

    /**
     * @param validationReqDTO
     * @return
     */
    public OAuth2TokenValidationResponseDTO validate(OAuth2TokenValidationRequestDTO validationReqDTO) {

        TokenValidationHandler validationHandler = TokenValidationHandler.getInstance();
        //trigger pre listeners
        try {
            triggerPreValidationListeners(validationReqDTO);
        } catch (IdentityOAuth2Exception e) {
            OAuth2TokenValidationResponseDTO errRespDTO = new OAuth2TokenValidationResponseDTO();
            errRespDTO.setValid(false);
            errRespDTO.setErrorMsg(e.getMessage());
            return errRespDTO;
        }
        OAuth2TokenValidationResponseDTO responseDTO = null;
        try {
            responseDTO = validationHandler.validate(validationReqDTO);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while validating the OAuth2 access token", e);
            responseDTO = new OAuth2TokenValidationResponseDTO();
            responseDTO.setValid(false);
            responseDTO.setErrorMsg("Server error occurred while validating the OAuth2 access token");
        }
        //trigger post listeners
        triggerPostValidationListeners(validationReqDTO, responseDTO);
        return responseDTO;
    }

    /**
     * @param validationReqDTO
     * @return
     */
    public OAuth2ClientApplicationDTO findOAuthConsumerIfTokenIsValid(
            OAuth2TokenValidationRequestDTO validationReqDTO) {

        TokenValidationHandler validationHandler = TokenValidationHandler.getInstance();

        try {
            return validationHandler.findOAuthConsumerIfTokenIsValid(validationReqDTO);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while validating the OAuth2 access token", e);
            OAuth2ClientApplicationDTO appDTO = new OAuth2ClientApplicationDTO();
            OAuth2TokenValidationResponseDTO errRespDTO = new OAuth2TokenValidationResponseDTO();
            errRespDTO.setValid(false);
            errRespDTO.setErrorMsg(e.getMessage());
            appDTO.setAccessTokenValidationResponse(errRespDTO);
            return appDTO;
        }
    }

    /**
     * returns back the introspection response, which is compatible with RFC 7662.
     *
     * @param validationReq
     * @return
     */
    public OAuth2IntrospectionResponseDTO buildIntrospectionResponse(OAuth2TokenValidationRequestDTO validationReq) {

        TokenValidationHandler validationHandler = TokenValidationHandler.getInstance();
        OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO = null;
        try {
            triggerPreValidationListeners(validationReq);
        } catch (IdentityOAuth2Exception e) {
            OAuth2IntrospectionResponseDTO errRespDTO = new OAuth2IntrospectionResponseDTO();
            errRespDTO.setActive(false);
            errRespDTO.setError(e.getMessage());
            triggerOnIntrospectionExceptionListeners(validationReq, errRespDTO);
            return errRespDTO;
        }
        try {
            oAuth2IntrospectionResponseDTO = validationHandler.buildIntrospectionResponse(validationReq);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while building the introspection response", e);
            oAuth2IntrospectionResponseDTO = new OAuth2IntrospectionResponseDTO();
            oAuth2IntrospectionResponseDTO.setActive(false);
            oAuth2IntrospectionResponseDTO.setError("Server error occurred while building the introspection response");
        }
        triggerPostIntrospectionValidationListeners(validationReq, oAuth2IntrospectionResponseDTO,
                oAuth2IntrospectionResponseDTO.getProperties());
        oAuth2IntrospectionResponseDTO.getProperties().remove(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT);

        return oAuth2IntrospectionResponseDTO;
    }

    private void triggerPreValidationListeners(OAuth2TokenValidationRequestDTO requestDTO)
            throws IdentityOAuth2Exception {
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            oAuthEventInterceptorProxy.onPreTokenValidation(requestDTO, paramMap);
        }
    }

    private void triggerPostValidationListeners(OAuth2TokenValidationRequestDTO requestDTO,
                                                OAuth2TokenValidationResponseDTO responseDTO) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy.onPostTokenValidation(requestDTO, responseDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth post validation listener failed.", e);
            }
        }
    }

    private void triggerPostIntrospectionValidationListeners(OAuth2TokenValidationRequestDTO requestDTO,
                                                             OAuth2IntrospectionResponseDTO responseDTO, Map<String,
            Object> paramMap) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                if (paramMap == null) {
                    paramMap = new HashMap<>();
                }
                oAuthEventInterceptorProxy.onPostTokenValidation(requestDTO, responseDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth post validation listener failed.", e);
            }
        }
    }
}
