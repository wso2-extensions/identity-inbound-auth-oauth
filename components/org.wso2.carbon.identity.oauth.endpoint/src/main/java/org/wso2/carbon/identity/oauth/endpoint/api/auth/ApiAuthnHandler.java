/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.auth.service.AuthServiceResponseData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthResponse;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Authenticator;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.AuthenticatorMetadata;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Context;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Link;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Message;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.Param;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.StepTypeEnum;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is responsible for building the response for the authentication API.
 */
public class ApiAuthnHandler {

    private static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";
    private static final String ADDITIONAL_DATA_REDIRECT_URL = "redirectUrl";
    private static final String AUTHENTICATION_EP = "/oauth2/authn";
    private static final String AUTHENTICATION_EP_LINK_NAME = "authentication";
    private static final String TENANT_CONTEXT_PATH_COMPONENT = "/t/%s";
    private static final String HTTP_POST = "POST";
    private static final String MESSAGE = "message";
    private static final String DOT_SEPARATOR = ".";

    /**
     * Build the response for the authentication API.
     *
     * @param authServiceResponse Response received from the Authentication Service.
     * @return AuthResponse
     * @throws AuthServiceException If an error occurs while building the response.
     */
    public AuthResponse handleResponse(AuthServiceResponse authServiceResponse) throws AuthServiceException {

        AuthResponse authResponse = new AuthResponse();
        authResponse.setFlowId(authServiceResponse.getSessionDataKey());
        authResponse.setFlowStatus(authServiceResponse.getFlowStatus());
        NextStep nextStep = buildNextStep(authServiceResponse);
        authResponse.setNextStep(nextStep);
        authResponse.setLinks(buildLinks());

        return authResponse;
    }

    private NextStep buildNextStep(AuthServiceResponse authServiceResponse) {

        NextStep nextStep = new NextStep();
        if (authServiceResponse.getData().isPresent()) {
            AuthServiceResponseData responseData = authServiceResponse.getData().get();
            nextStep.setStepType(getStepType(responseData.isAuthenticatorSelectionRequired()));
            List<Authenticator> authenticators = new ArrayList<>();
            responseData.getAuthenticatorOptions().forEach(authenticatorData -> {
                Authenticator authenticator = buildAuthenticatorData(authenticatorData);
                authenticators.add(authenticator);
            });
            nextStep.setAuthenticators(authenticators);
        }

        List<Message> messages = buildMessages(authServiceResponse);
        nextStep.setMessages(messages);

        return nextStep;
    }

    private Authenticator buildAuthenticatorData(AuthenticatorData authenticatorData) {

        Authenticator authenticator = new Authenticator();
        authenticator.setAuthenticatorId(buildAuthenticatorId(authenticatorData.getName(),
                authenticatorData.getIdp()));
        authenticator.setAuthenticator(authenticatorData.getDisplayName());
        authenticator.setIdp(authenticatorData.getIdp());
        AuthenticatorMetadata metadata = buildAuthenticatorMetadata(authenticatorData);
        authenticator.setMetadata(metadata);
        authenticator.setRequiredParams(authenticatorData.getRequiredParams());
        return authenticator;
    }

    private List<Message> buildMessages(AuthServiceResponse authServiceResponse) {

        List<Message> messages = new ArrayList<>();
        boolean hasErrorMessageFromAuthenticator = false;
        if (authServiceResponse.getData().isPresent()) {
            AuthServiceResponseData responseData = authServiceResponse.getData().get();
            for (AuthenticatorData authenticatorData : responseData.getAuthenticatorOptions()) {
                if (authenticatorData.getMessage() != null) {
                    Message message = new Message();
                    if (authenticatorData.getMessage().getType() == FrameworkConstants.AuthenticatorMessageType.ERROR) {
                        hasErrorMessageFromAuthenticator = true;
                    }
                    message.setType(authenticatorData.getMessage().getType());
                    message.setMessageId(authenticatorData.getMessage().getCode());
                    message.setMessage(authenticatorData.getMessage().getMessage());
                    message.setI18nKey(getMessageI18nKey(authenticatorData.getMessage().getCode()));
                    if (MapUtils.isNotEmpty(authenticatorData.getMessage().getContext())) {
                        message.setContext(buildMessageContext(authenticatorData.getMessage().getContext()));
                    }
                    message.setContext(buildMessageContext(authenticatorData.getMessage().getContext()));

                }
            }
        }

        // If there are no error messages from authenticators, check for error info.
        if (!hasErrorMessageFromAuthenticator && authServiceResponse.getErrorInfo().isPresent()) {
            Message errorMessage = new Message();
            errorMessage.setType(FrameworkConstants.AuthenticatorMessageType.ERROR);
            errorMessage.setMessageId(authServiceResponse.getErrorInfo().get().getErrorCode());
            errorMessage.setMessage(authServiceResponse.getErrorInfo().get().getErrorMessage());
            errorMessage.setI18nKey(getMessageI18nKey(authServiceResponse.getErrorInfo().get().getErrorCode()));
            messages.add(errorMessage);
        }
        return messages;
    }

    private String getMessageI18nKey(String messageId) {

        return MESSAGE + DOT_SEPARATOR + messageId;
    }

    private List<Context> buildMessageContext(Map<String, String> contextData) {

        List<Context> contextList = new ArrayList<>();
        contextData.forEach((key, value) -> {
            Context context = new Context();
            context.setKey(key);
            context.setValue(value);
            contextList.add(context);
        });
        return contextList;
    }

    private AuthenticatorMetadata buildAuthenticatorMetadata(AuthenticatorData authenticatorData) {

        AuthenticatorMetadata authenticatorMetadata = new AuthenticatorMetadata();
        authenticatorMetadata.setI18nKey(authenticatorData.getI18nKey());
        if (isAdditionalAuthenticatorDataAvailable(authenticatorData)) {
            authenticatorMetadata.setPromptType(authenticatorData.getPromptType());
            List<Param> params = new ArrayList<>();
            for (AuthenticatorParamMetadata paramMetadata : authenticatorData.getAuthParams()) {
                Param param = buildAuthenticatorParam(paramMetadata);
                params.add(param);
            }
            authenticatorMetadata.setParams(params);
            if (authenticatorData.getAdditionalData() != null) {
                authenticatorMetadata.setAdditionalData(getAdditionalData(authenticatorData.getAdditionalData()));
            }
        }
        return authenticatorMetadata;
    }

    private boolean isAdditionalAuthenticatorDataAvailable(AuthenticatorData authenticatorData) {

        // We can assume if required params are empty that other additional data is also empty.
        return !authenticatorData.getRequiredParams().isEmpty();
    }

    private Map<String, String> getAdditionalData(AdditionalData additionalData) {

        Map<String, String> additionalDataMap = new HashMap<>(additionalData.getAdditionalAuthenticationParams());
        if (StringUtils.isNotBlank(additionalData.getRedirectUrl())) {
            additionalDataMap.put(ADDITIONAL_DATA_REDIRECT_URL, additionalData.getRedirectUrl());
        }
        return additionalDataMap;
    }

    private Param buildAuthenticatorParam(AuthenticatorParamMetadata paramMetadata) {

        Param param = new Param();
        param.setParam(paramMetadata.getName());
        param.setType(paramMetadata.getType());
        param.setConfidential(paramMetadata.isConfidential());
        param.setOrder(paramMetadata.getParamOrder());
        param.setI18nKey(paramMetadata.getI18nKey());

        return param;
    }

    private List<Link> buildLinks() throws AuthServiceException {

        List<Link> links = new ArrayList<>();
        Link authnEpLink = new Link();
        authnEpLink.setName(AUTHENTICATION_EP_LINK_NAME);
        String endpoint = AUTHENTICATION_EP;
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            endpoint = String.format(TENANT_CONTEXT_PATH_COMPONENT, getTenantDomainFromContext()) + AUTHENTICATION_EP;
        }
        String href;
        try {
            href = ServiceURLBuilder.create().addPath(endpoint).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthServiceException(AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED.code(),
                    "Error occurred while building links", e);
        }
        authnEpLink.setHref(href);
        authnEpLink.setMethod(HTTP_POST);
        links.add(authnEpLink);
        return links;
    }

    private String getTenantDomainFromContext() {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT) != null) {
            tenantDomain = (String) IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT);
        }
        return tenantDomain;
    }

    private String buildAuthenticatorId(String authenticator, String idp) {

        return base64URLEncode(authenticator + OAuthConstants.AUTHENTICATOR_IDP_SPLITTER + idp);
    }

    private StepTypeEnum getStepType(boolean isMultiOps) {

        if (isMultiOps) {
            return StepTypeEnum.MULTI_OPTIONS_PROMPT;
        } else {
            return StepTypeEnum.AUTHENTICATOR_PROMPT;
        }
    }

    private String base64URLEncode(String value) {

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
