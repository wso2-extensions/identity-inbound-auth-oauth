/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authcontext.AuthorizationContextTokenGenerator;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Handles the token validation by invoking the proper validation handler by looking at the token
 * type.
 */
public class TokenValidationHandler {

    private static TokenValidationHandler instance = null;
    AuthorizationContextTokenGenerator tokenGenerator = null;
    private Log log = LogFactory.getLog(TokenValidationHandler.class);
    private Map<String, OAuth2TokenValidator> tokenValidators = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private static final String BUILD_FQU_FROM_SP_CONFIG = "OAuth.BuildSubjectIdentifierFromSPConfig";

    private TokenValidationHandler() {

        tokenValidators.put(DefaultOAuth2TokenValidator.TOKEN_TYPE, new DefaultOAuth2TokenValidator());
        tokenValidators.put(RefreshTokenValidator.TOKEN_TYPE, new RefreshTokenValidator());

        for (Map.Entry<String, String> entry : OAuthServerConfiguration.getInstance().getTokenValidatorClassNames()
                .entrySet()) {
            String className = null;
            try {
                String type = entry.getKey();
                className = entry.getValue();
                Class clazz = Thread.currentThread().getContextClassLoader().loadClass(entry.getValue());
                OAuth2TokenValidator tokenValidator = (OAuth2TokenValidator) clazz.newInstance();
                tokenValidators.put(type, tokenValidator);
            } catch (ClassNotFoundException e) {
                log.error("Class not in build path " + className, e);
            } catch (InstantiationException e) {
                log.error("Class initialization error " + className, e);
            } catch (IllegalAccessException e) {
                log.error("Class access error " + className, e);
            }
        }

        // setting up the JWT if required
        if (OAuthServerConfiguration.getInstance().isAuthContextTokGenEnabled()) {
            try {
                Class clazz = this.getClass().getClassLoader().loadClass(OAuthServerConfiguration.getInstance()
                        .getTokenGeneratorImplClass());
                tokenGenerator = (AuthorizationContextTokenGenerator) clazz.newInstance();
                tokenGenerator.init();
                if (log.isDebugEnabled()) {
                    log.debug("An instance of " + OAuthServerConfiguration.getInstance().getTokenGeneratorImplClass() +
                            " is created for OAuthServerConfiguration.");
                }
            } catch (ClassNotFoundException e) {
                String errorMsg = "Class not found: " +
                        OAuthServerConfiguration.getInstance().getTokenGeneratorImplClass();
                log.error(errorMsg, e);
            } catch (InstantiationException e) {
                String errorMsg = "Error while instantiating: " +
                        OAuthServerConfiguration.getInstance().getTokenGeneratorImplClass();
                log.error(errorMsg, e);
            } catch (IllegalAccessException e) {
                String errorMsg = "Illegal access to: " +
                        OAuthServerConfiguration.getInstance().getTokenGeneratorImplClass();
                log.error(errorMsg, e);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error while initializing: " +
                        OAuthServerConfiguration.getInstance().getTokenGeneratorImplClass();
                log.error(errorMsg, e);
            }
        }
    }

    public static TokenValidationHandler getInstance() {
        if (instance == null) {
            synchronized (TokenValidationHandler.class) {
                if (instance == null) {
                    instance = new TokenValidationHandler();
                }
            }
        }
        return instance;
    }

    public void addTokenValidator(String type, OAuth2TokenValidator handler) {
        tokenValidators.put(type, handler);
    }

    /**
     * @param requestDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    public OAuth2TokenValidationResponseDTO validate(OAuth2TokenValidationRequestDTO requestDTO)
            throws IdentityOAuth2Exception {

        OAuth2ClientApplicationDTO appToken = findOAuthConsumerIfTokenIsValid(requestDTO);
        return appToken.getAccessTokenValidationResponse();
    }

    /**
     * this is method is deprecated now. any new implementations use buildIntrospectionResponse.
     *
     * @param requestDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Deprecated
    public OAuth2ClientApplicationDTO findOAuthConsumerIfTokenIsValid(OAuth2TokenValidationRequestDTO requestDTO)
            throws IdentityOAuth2Exception {

        OAuth2ClientApplicationDTO clientApp = new OAuth2ClientApplicationDTO();
        OAuth2TokenValidationResponseDTO responseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2TokenValidationMessageContext messageContext =
                new OAuth2TokenValidationMessageContext(requestDTO, responseDTO);

        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = requestDTO.getAccessToken();
        OAuth2TokenValidator tokenValidator = null;
        AccessTokenDO accessTokenDO = null;

        try {
            tokenValidator = findAccessTokenValidator(accessToken);
        } catch (IllegalArgumentException e) {
            // access token not provided.
            return buildClientAppErrorResponse(e.getMessage());
        }

        try {
            accessTokenDO = OAuth2Util.findAccessToken(requestDTO.getAccessToken().getIdentifier(), false);
        } catch (IllegalArgumentException e) {
            // Access token not found in the system.
            return buildClientAppErrorResponse(e.getMessage());
        }

        if (hasAccessTokenExpired(accessTokenDO)) {
            return buildClientAppErrorResponse("Access token expired");
        }
        // Set the token expiration time
        responseDTO.setExpiryTime(getAccessTokenExpirationTime(accessTokenDO));

        // Adding the AccessTokenDO as a context property for further use
        messageContext.addProperty("AccessTokenDO", accessTokenDO);

        if (!tokenValidator.validateAccessDelegation(messageContext)) {
            return buildClientAppErrorResponse("Invalid access delegation");
        }

        if (!tokenValidator.validateScope(messageContext)) {
            return buildClientAppErrorResponse("Scope validation failed");
        }

        if (!tokenValidator.validateAccessToken(messageContext)) {
            return buildClientAppErrorResponse("OAuth2 access token validation failed");
        }

        responseDTO.setAuthorizedUser(getAuthzUser(accessTokenDO));
        responseDTO.setScope(accessTokenDO.getScope());
        responseDTO.setValid(true);

        if (tokenGenerator != null) {
            tokenGenerator.generateToken(messageContext);
            if (log.isDebugEnabled()) {
                log.debug(tokenGenerator.getClass().getName() + " generated token set to response");
            }
        }

        clientApp.setAccessTokenValidationResponse(responseDTO);
        clientApp.setConsumerKey(accessTokenDO.getConsumerKey());
        return clientApp;
    }

    /**
     * returns back the introspection response, which is compatible with RFC 7662.
     *
     * @param validationRequest
     * @return
     * @throws IdentityOAuth2Exception
     */
    public OAuth2IntrospectionResponseDTO buildIntrospectionResponse(OAuth2TokenValidationRequestDTO validationRequest)
            throws IdentityOAuth2Exception {

        OAuth2TokenValidationResponseDTO responseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2IntrospectionResponseDTO introResp = new OAuth2IntrospectionResponseDTO();

        OAuth2TokenValidationMessageContext messageContext =
                new OAuth2TokenValidationMessageContext(validationRequest, responseDTO);

        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2Token = validationRequest.getAccessToken();

        // To hold the applicable validators list from all the available validators. This list will be prioritized if we
        // have a token_type_hint.
        List<OAuth2TokenValidator> applicableValidators = new ArrayList<>();

        // If we have a token type hint, we have to prioritize our list.
        if (oAuth2Token.getTokenType() != null) {
            if (tokenValidators.get(oAuth2Token.getTokenType()) != null) {
                applicableValidators.add(tokenValidators.get(oAuth2Token.getTokenType()));
            }
        }

        // Add the rest of the validators.
        for (Map.Entry<String, OAuth2TokenValidator> oAuth2TokenValidator : tokenValidators.entrySet()) {
            // Ignore if we added this already.
            if (StringUtils.equals(oAuth2TokenValidator.getKey(), oAuth2Token.getTokenType())) {
                continue;
            }
            if (oAuth2TokenValidator.getValue() != null) {
                applicableValidators.add(oAuth2TokenValidator.getValue());
            }
        }

        // Catch the latest exception and throw it if there aren't any active tokens.
        Exception exception = null;
        for (OAuth2TokenValidator tokenValidator : applicableValidators) {
            try {
                if (tokenValidator.validateAccessToken(messageContext)) {
                    // We have to specially handle the access token and refresh token for further validations.
                    if (tokenValidator instanceof DefaultOAuth2TokenValidator) {
                        introResp = validateAccessToken(messageContext, validationRequest, tokenValidator);
                    } else if (tokenValidator instanceof RefreshTokenValidator) {
                        introResp = validateRefreshToken(messageContext, validationRequest, tokenValidator);
                    }
                    // If there aren't any errors from the above special validations.
                    if (introResp.isActive()) {
                        introResp.setTokenType(tokenValidator.getTokenType());
                        break;
                    }
                }
            } catch (Exception ex) {
                exception = ex;
            }
        }

        // If there aren't any active tokens, then there should be an error or exception. If no error or exception
        // as well, that means this token is not active. So show the generic error.
        if (!introResp.isActive()) {
            if (introResp.getError() != null) {
                return introResp;
            } else if (exception != null) {
                throw new IdentityOAuth2Exception("Error occurred while validating token.", exception);
            } else {
                return buildIntrospectionErrorResponse("Token validation failed");
            }
        }

        if (introResp.getUsername() != null) {
            responseDTO.setAuthorizedUser(introResp.getUsername());
        }

        if (tokenGenerator != null) {
            // add user attributes to the introspection response.
            tokenGenerator.generateToken(messageContext);
            if (log.isDebugEnabled()) {
                log.debug(tokenGenerator.getClass().getName() + " generated token set to response");
            }
            if (responseDTO.getAuthorizationContextToken() != null) {
                introResp.setUserContext(responseDTO.getAuthorizationContextToken().getTokenString());
            }
        }

        introResp.getProperties().put(OAuth2Util.OAUTH2_VALIDATION_MESSAGE_CONTEXT, messageContext);
        return introResp;
    }

    private OAuth2IntrospectionResponseDTO validateRefreshToken(OAuth2TokenValidationMessageContext messageContext,
                                                                OAuth2TokenValidationRequestDTO validationRequest,
                                                                OAuth2TokenValidator tokenValidator)
            throws IdentityOAuth2Exception {

        OAuth2IntrospectionResponseDTO introResp = new OAuth2IntrospectionResponseDTO();
        AccessTokenDO refreshTokenDataDO;

        try {
            refreshTokenDataDO = findRefreshToken(validationRequest.getAccessToken().getIdentifier());
        } catch (IllegalArgumentException e) {
            // Refresh token not found in the system.
            return buildIntrospectionErrorResponse(e.getMessage());
        }

        if (refreshTokenDataDO == null || hasRefreshTokenExpired(refreshTokenDataDO)) {
            // Token is not active. we do not need to worry about other details.
            introResp.setActive(false);
            return introResp;
        }

        // should be in seconds
        introResp.setExp((refreshTokenDataDO.getValidityPeriodInMillis() + refreshTokenDataDO.getIssuedTime().getTime())
                / 1000);
        // should be in seconds
        introResp.setIat(refreshTokenDataDO.getIssuedTime().getTime() / 1000);
        // Not before time will be the same as issued time.
        introResp.setNbf(refreshTokenDataDO.getIssuedTime().getTime() / 1000);
        // Token scopes.
        introResp.setScope(OAuth2Util.buildScopeString((refreshTokenDataDO.getScope())));
        // Set user-name.
        introResp.setUsername(getAuthzUser(refreshTokenDataDO));
        // Add client id.
        introResp.setClientId(refreshTokenDataDO.getConsumerKey());
        // Adding the AccessTokenDO as a context property for further use.
        messageContext.addProperty("RefreshTokenDO", refreshTokenDataDO);

        // Validate access delegation.
        if (!tokenValidator.validateAccessDelegation(messageContext)) {
            // This is redundant. But for sake of readability.
            introResp.setActive(false);
            return buildIntrospectionErrorResponse("Invalid access delegation");
        }

        // Validate scopes.
        if (!tokenValidator.validateScope(messageContext)) {
            // This is redundant. But for sake of readability.
            introResp.setActive(false);
            return buildIntrospectionErrorResponse("Scope validation failed");
        }

        // All set. mark the token active.
        introResp.setActive(true);
        return introResp;
    }

    private OAuth2IntrospectionResponseDTO validateAccessToken(OAuth2TokenValidationMessageContext messageContext,
                                                               OAuth2TokenValidationRequestDTO validationRequest,
                                                               OAuth2TokenValidator tokenValidator)
            throws IdentityOAuth2Exception {

        OAuth2IntrospectionResponseDTO introResp = new OAuth2IntrospectionResponseDTO();
        AccessTokenDO accessTokenDO;

        if (messageContext.getProperty(OAuth2Util.REMOTE_ACCESS_TOKEN) != null
                && "true".equalsIgnoreCase((String) messageContext.getProperty(OAuth2Util.REMOTE_ACCESS_TOKEN))) {
            // this can be a self-issued JWT or any access token issued by a trusted OAuth authorization server.

            // should be in seconds
            if (messageContext.getProperty(OAuth2Util.EXP) != null) {
                introResp.setExp(Long.parseLong((String) messageContext.getProperty(OAuth2Util.EXP)));
            }
            // should be in seconds
            if (messageContext.getProperty(OAuth2Util.IAT) != null) {
                introResp.setIat(Long.parseLong((String) messageContext.getProperty(OAuth2Util.IAT)));
            }

            // token scopes - space delimited
            if (messageContext.getProperty(OAuth2Util.SCOPE) != null) {
                introResp.setScope((String) messageContext.getProperty(OAuth2Util.SCOPE));
            }
            // set user-name
            if (messageContext.getProperty(OAuth2Util.USERNAME) != null) {
                introResp.setUsername((String) messageContext.getProperty(OAuth2Util.USERNAME));
            }
            // set client-id
            if (messageContext.getProperty(OAuth2Util.CLIENT_ID) != null) {
                introResp.setClientId((String) messageContext.getProperty(OAuth2Util.CLIENT_ID));
            }

        } else {

            try {
                accessTokenDO = OAuth2Util.findAccessToken(validationRequest.getAccessToken().getIdentifier(), false);
            } catch (IllegalArgumentException e) {
                // access token not found in the system.
                return buildIntrospectionErrorResponse(e.getMessage());
            }

            if (hasAccessTokenExpired(accessTokenDO)) {
                // token is not active. we do not need to worry about other details.
                introResp.setActive(false);
                return introResp;
            }

            // should be in seconds
            introResp.setExp((accessTokenDO.getValidityPeriodInMillis() + accessTokenDO.getIssuedTime().getTime())
                    / 1000);
            // should be in seconds
            introResp.setIat(accessTokenDO.getIssuedTime().getTime() / 1000);
            // Not before time will be the same as issued time.
            introResp.setNbf(accessTokenDO.getIssuedTime().getTime() / 1000);
            // token scopes
            introResp.setScope(OAuth2Util.buildScopeString((accessTokenDO.getScope())));
            // set user-name
            introResp.setUsername(getAuthzUser(accessTokenDO));
            // add client id
            introResp.setClientId(accessTokenDO.getConsumerKey());
            // adding the AccessTokenDO as a context property for further use
            messageContext.addProperty("AccessTokenDO", accessTokenDO);
        }

        if (messageContext.getProperty(OAuth2Util.JWT_ACCESS_TOKEN) != null
                && "true".equalsIgnoreCase((String) messageContext.getProperty(OAuth2Util.JWT_ACCESS_TOKEN))) {
            // attributes only related JWT access tokens.

            if (messageContext.getProperty(OAuth2Util.SUB) != null) {
                introResp.setSub((String) messageContext.getProperty(OAuth2Util.SUB));
            }
            if (messageContext.getProperty(OAuth2Util.ISS) != null) {
                introResp.setIss((String) messageContext.getProperty(OAuth2Util.ISS));
            }
            if (messageContext.getProperty(OAuth2Util.AUD) != null) {
                introResp.setAud((String) messageContext.getProperty(OAuth2Util.AUD));
            }
            if (messageContext.getProperty(OAuth2Util.JTI) != null) {
                introResp.setJti((String) messageContext.getProperty(OAuth2Util.JTI));
            }
            // set the token not to be used before time in seconds
            if (messageContext.getProperty(OAuth2Util.NBF) != null) {
                introResp.setNbf(Long.parseLong((String) messageContext.getProperty(OAuth2Util.NBF)));
            }
        }

        // Validate access delegation.
        if (!tokenValidator.validateAccessDelegation(messageContext)) {
            // This is redundant. But sake of readability.
            introResp.setActive(false);
            return buildIntrospectionErrorResponse("Invalid access delegation");
        }

        // Validate scopes.
        if (!tokenValidator.validateScope(messageContext)) {
            // This is redundant. But sake of readability.
            introResp.setActive(false);
            return buildIntrospectionErrorResponse("Scope validation failed");
        }

        // All set. mark the token active.
        introResp.setActive(true);
        return introResp;
    }

    private String getAuthzUser(AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {

        AuthenticatedUser user = accessTokenDO.getAuthzUser();

        if (user.isFederatedUser()) {
            return user.getAuthenticatedSubjectIdentifier();
        }

        String consumerKey = accessTokenDO.getConsumerKey();
        try {
            boolean buildSubjectIdentifierFromSPConfig = true;
            String subjectIdentifierFromSPConfig = IdentityUtil.getProperty(BUILD_FQU_FROM_SP_CONFIG);
            if (StringUtils.isNotEmpty(subjectIdentifierFromSPConfig)) {
                buildSubjectIdentifierFromSPConfig =
                        Boolean.parseBoolean(subjectIdentifierFromSPConfig);
            }

            if (buildSubjectIdentifierFromSPConfig) {
                ServiceProvider serviceProvider = getServiceProvider(consumerKey);
                boolean useTenantDomainInLocalSubjectIdentifier = serviceProvider
                        .getLocalAndOutBoundAuthenticationConfig().isUseTenantDomainInLocalSubjectIdentifier();
                boolean useUserStoreDomainInLocalSubjectIdentifier = serviceProvider
                        .getLocalAndOutBoundAuthenticationConfig().isUseUserstoreDomainInLocalSubjectIdentifier();
                return user.getUsernameAsSubjectIdentifier(useUserStoreDomainInLocalSubjectIdentifier,
                        useTenantDomainInLocalSubjectIdentifier);
            } else {
                return user.toFullQualifiedUsername();
            }
        } catch (IdentityApplicationManagementException | InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id:" +
                    consumerKey, e);
        }
    }

    private ServiceProvider getServiceProvider(String consumerKey) throws IdentityApplicationManagementException,
            IdentityOAuth2Exception, InvalidOAuthClientException {
        String spTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(consumerKey);
        return OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(consumerKey,
                OAuthConstants.Scope.OAUTH2, spTenantDomain);
    }

    /**
     * @param errorMessage
     * @return
     */
    private OAuth2ClientApplicationDTO buildClientAppErrorResponse(String errorMessage) {
        OAuth2TokenValidationResponseDTO responseDTO = new OAuth2TokenValidationResponseDTO();
        OAuth2ClientApplicationDTO clientApp = new OAuth2ClientApplicationDTO();
        if (log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        responseDTO.setValid(false);
        responseDTO.setErrorMsg(errorMessage);
        clientApp.setAccessTokenValidationResponse(responseDTO);
        return clientApp;
    }

    /**
     * @param errorMessage
     * @return
     */
    private OAuth2IntrospectionResponseDTO buildIntrospectionErrorResponse(String errorMessage) {
        OAuth2IntrospectionResponseDTO response = new OAuth2IntrospectionResponseDTO();
        if (log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        response.setActive(false);
        response.setError(errorMessage);
        return response;
    }

    /**
     * @param accessToken
     * @return
     * @throws IdentityOAuth2Exception
     */
    private OAuth2TokenValidator findAccessTokenValidator(OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken)
            throws IdentityOAuth2Exception {
        // incomplete token validation request
        if (accessToken == null) {
            throw new IllegalArgumentException("Access token is not present in the validation request");
        }

        String accessTokenIdentifier = accessToken.getIdentifier();
        // incomplete token validation request
        if (accessTokenIdentifier == null) {
            throw new IllegalArgumentException("Access token identifier is not present in the validation request");
        }

        OAuth2TokenValidator tokenValidator = tokenValidators.get(accessToken.getTokenType());

        // There is no token validator for the provided token type.
        if (tokenValidator == null) {
            throw new IllegalArgumentException("Unsupported access token type: " + accessToken.getTokenType());
        }

        return tokenValidator;
    }

    /**
     * @param accessTokenDO
     * @return
     */
    private long getAccessTokenExpirationTime(AccessTokenDO accessTokenDO) {
        long expiryTime = OAuth2Util.getAccessTokenExpireMillis(accessTokenDO);

        if (OAuthConstants.UserType.APPLICATION_USER.equals(accessTokenDO.getTokenType())
                && OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds() < 0) {
            return Long.MAX_VALUE;
        } else if (OAuthConstants.UserType.APPLICATION.equals(accessTokenDO.getTokenType())
                && OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds() < 0) {
            return Long.MAX_VALUE;
        } else if (expiryTime < 0) {
            return Long.MAX_VALUE;
        }

        return expiryTime / 1000;
    }

    /**
     * @param accessTokenDO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private boolean hasAccessTokenExpired(AccessTokenDO accessTokenDO) {
        // check whether the grant is expired
        if (accessTokenDO.getValidityPeriod() < 0) {
            if (log.isDebugEnabled()) {
                log.debug("Access Token has infinite lifetime");
            }
        } else {
            if (OAuth2Util.getAccessTokenExpireMillis(accessTokenDO) == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Access Token has expired");
                }
                return true;
            }
        }

        return false;
    }

    private boolean hasRefreshTokenExpired(AccessTokenDO accessTokenDO) {

        if (accessTokenDO.getRefreshTokenValidityPeriodInMillis() < 0) {
            if (log.isDebugEnabled()) {
                log.debug("Access Token has infinite lifetime");
            }
        } else {
            if (OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO) == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Access Token has expired");
                }
                return true;
            }
        }

        return false;
    }

    private AccessTokenDO findRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        return OAuthTokenPersistenceFactory.getInstance().getTokenManagementDAO().getRefreshToken(refreshToken);
    }
}
