/*
 * Copyright (c) 2019-2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.authcontext.AuthorizationContextTokenGenerator;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IS_FRAGMENT_APP;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isParsableJWT;

/**
 * Handles the token validation by invoking the proper validation handler by looking at the token
 * type.
 */
public class TokenValidationHandler {

    private static TokenValidationHandler instance = null;
    AuthorizationContextTokenGenerator tokenGenerator = null;
    private static final Log log = LogFactory.getLog(TokenValidationHandler.class);
    private Map<String, OAuth2TokenValidator> tokenValidators = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private TokenProvider tokenValidationProcessor;
    private static final String BEARER_TOKEN_TYPE = "Bearer";
    private static final String DPOP_TOKEN_TYPE = "DPoP";
    private static final String BEARER_TOKEN_TYPE_JWT = "jwt";
    private static final String BUILD_FQU_FROM_SP_CONFIG = "OAuth.BuildSubjectIdentifierFromSPConfig";
    private static final String ENABLE_JWT_TOKEN_VALIDATION = "OAuth.EnableJWTTokenValidationDuringIntrospection";
    private static final String AUTHORIZATION_CODE = "authorizationCode";

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
        tokenValidationProcessor = OAuth2ServiceComponentHolder.getInstance().getTokenProvider();
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
            accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(requestDTO.getAccessToken().getIdentifier(), false);
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
        messageContext.addProperty(OAuthConstants.ACCESS_TOKEN_DO, accessTokenDO);

        if (!tokenValidator.validateAccessDelegation(messageContext)) {
            return buildClientAppErrorResponse("Invalid access delegation");
        }

        if (!tokenValidator.validateScope(messageContext)) {
            return buildClientAppErrorResponse("Scope validation failed at app level");
        }

        if (!tokenValidator.validateAccessToken(messageContext)) {
            return buildClientAppErrorResponse("OAuth2 access token validation failed");
        }

        responseDTO.setAuthorizedUser(getAuthzUser(accessTokenDO));
        responseDTO.setScope(accessTokenDO.getScope());
        responseDTO.setValid(true);
        responseDTO.setTokenBinding(accessTokenDO.getTokenBinding());

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
        boolean isJWTTokenValidation = isJWTTokenValidation(oAuth2Token.getIdentifier());

        // If we have a token type hint, we have to prioritize our list.
        if (oAuth2Token.getTokenType() != null) {
            if (tokenValidators.get(oAuth2Token.getTokenType()) != null) {
                // Ignore bearer token validators if the token is JWT.
                if (!isSkipValidatorForJWT(tokenValidators.get(oAuth2Token.getTokenType()), isJWTTokenValidation)) {
                    applicableValidators.add(tokenValidators.get(oAuth2Token.getTokenType()));
                }
            }
        }

        // Add the rest of the validators.
        for (Map.Entry<String, OAuth2TokenValidator> oAuth2TokenValidator : tokenValidators.entrySet()) {
            // Ignore if we added this already.
            if (StringUtils.equals(oAuth2TokenValidator.getKey(), oAuth2Token.getTokenType())) {
                continue;
            }

            // Ignore bearer token validators if the token is JWT.
            if (isSkipValidatorForJWT(oAuth2TokenValidator.getValue(), isJWTTokenValidation)) {
                continue;
            }

            if (oAuth2TokenValidator.getValue() != null) {
                applicableValidators.add(oAuth2TokenValidator.getValue());
            }
        }

        // Adding the AccessTokenDO as a context property for further use
        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(oAuth2Token.getIdentifier(), true);
            if (accessTokenDO != null) {
                messageContext.addProperty(OAuthConstants.ACCESS_TOKEN_DO, accessTokenDO);
            }
        } catch (IllegalArgumentException e) {
            return buildIntrospectionErrorResponse(e.getMessage());
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
                    if (log.isDebugEnabled()) {
                        log.debug("Introspecting token of the application:" + introResp.getClientId() + " using the"
                                + " token validator " + tokenValidator.getClass().getName());
                    }
                    // If there aren't any errors from the above special validations.
                    if (introResp.isActive()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Introspecting token is active for the application:" + introResp.getClientId());
                        }
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
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_ACCESS_TOKEN);
                diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
            }
            if (introResp.getError() != null) {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage(introResp.getError());
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return introResp;
            } else if (exception != null) {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, exception.getMessage())
                            .resultMessage("System error occurred.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                throw new IdentityOAuth2Exception("Error occurred while validating token.", exception);
            } else {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                if (diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("Token validation failed.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return buildIntrospectionErrorResponse("Token validation failed");
            }
        }

        if (introResp.getUsername() != null) {
            responseDTO.setAuthorizedUser(introResp.getUsername());
        }

        if (tokenGenerator != null && validationRequest.getRequiredClaimURIs() != null) {
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
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_REFRESH_TOKEN);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        try {
            refreshTokenDataDO = findRefreshToken(validationRequest.getAccessToken().getIdentifier());
        } catch (IllegalArgumentException e) {
            // Refresh token not found in the system.
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .resultMessage("Provided token is not a valid refresh token.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return buildIntrospectionErrorResponse(e.getMessage());
        }

        if (refreshTokenDataDO == null || hasRefreshTokenExpired(refreshTokenDataDO)) {
            if (refreshTokenDataDO == null) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                    diagnosticLogBuilder.resultMessage("Provided token is not a valid refresh token.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            } else if (hasRefreshTokenExpired(refreshTokenDataDO)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                    diagnosticLogBuilder.resultMessage("Token is expired.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            }
            // Token is not active. we do not need to worry about other details.
            introResp.setActive(false);
            return introResp;
        }

        // should be in seconds
        introResp.setExp((refreshTokenDataDO.getRefreshTokenValidityPeriodInMillis()
                + refreshTokenDataDO.getRefreshTokenIssuedTime().getTime()) / 1000);
        // should be in seconds
        introResp.setIat(refreshTokenDataDO.getRefreshTokenIssuedTime().getTime() / 1000);
        // Not before time will be the same as issued time.
        introResp.setNbf(refreshTokenDataDO.getRefreshTokenIssuedTime().getTime() / 1000);
        // Token scopes.
        introResp.setScope(OAuth2Util.buildScopeString((refreshTokenDataDO.getScope())));
        // Set user-name.
        introResp.setUsername(getAuthzUser(refreshTokenDataDO));
        // Add client id.
        introResp.setClientId(refreshTokenDataDO.getConsumerKey());
        // Adding the AccessTokenDO as a context property for further use.
        messageContext.addProperty("RefreshTokenDO", refreshTokenDataDO);
        // Add authenticated user object since username attribute may not have the domain appended if the
        // subject identifier is built based in the SP config.
        introResp.setAuthorizedUser(refreshTokenDataDO.getAuthzUser());
        // Add acr and auth_time
        setAcrAndAuthTimeClaims(introResp, validationRequest);

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
            throws IdentityOAuth2Exception, IdentityApplicationManagementException, InvalidOAuthClientException {

        OAuth2IntrospectionResponseDTO introResp = new OAuth2IntrospectionResponseDTO();
        AccessTokenDO accessTokenDO = null;
        List<String> requestedAllowedScopes = new ArrayList<>();

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.VALIDATE_ACCESS_TOKEN);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
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
                String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                        .getVerifiedAccessToken(validationRequest.getAccessToken().getIdentifier(), false);
                /*
                 Check if the OAuth application is a fragment application. If that is not a fragment application,
                 then getting the tenant domain from the token.
                */
                String appTenantDomain = IdentityTenantUtil.getTenantDomain(accessTokenDO.getTenantID());
                if (OrganizationManagementUtil.isOrganization(appTenantDomain)) {
                    ServiceProviderProperty[] serviceProviderProperties = OAuth2Util.getServiceProvider(
                            accessTokenDO.getConsumerKey(), appTenantDomain).getSpProperties();
                    if (!isFragmentApp(serviceProviderProperties)) {
                        tenantDomain = appTenantDomain;
                    }
                }
                boolean isCrossTenantTokenIntrospectionAllowed
                        = OAuthServerConfiguration.getInstance().isCrossTenantTokenIntrospectionAllowed();
                if (!isCrossTenantTokenIntrospectionAllowed && accessTokenDO != null &&
                        !tenantDomain.equalsIgnoreCase(accessTokenDO.getAuthzUser().getTenantDomain()) &&
                        StringUtils.isEmpty(accessTokenDO.getAuthzUser().getAccessingOrganization())) {
                    throw new IllegalArgumentException("Invalid Access Token. ACTIVE access token is not found.");
                }
                List<String> allowedScopes = OAuthServerConfiguration.getInstance().getAllowedScopes();
                String[] requestedScopes = accessTokenDO.getScope();
                List<String> scopesToBeValidated = new ArrayList<>();
                if (requestedScopes != null) {
                    for (String scope : requestedScopes) {
                        if (OAuth2Util.isAllowedScope(allowedScopes, scope)) {
                            requestedAllowedScopes.add(scope);
                        } else {
                            scopesToBeValidated.add(scope);
                        }
                    }
                    accessTokenDO.setScope(scopesToBeValidated.toArray(new String[0]));
                }
            } catch (IllegalArgumentException e) {
                // access token not found in the system.
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                            .resultMessage("Provided token is not a valid access token.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                return buildIntrospectionErrorResponse(e.getMessage());
            } catch (OrganizationManagementException e) {
                throw new IdentityOAuth2Exception("Error while checking whether the application tenant is an " +
                        "organization.", e);
            }

            if (hasAccessTokenExpired(accessTokenDO)) {
                if (diagnosticLogBuilder != null) {
                    // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                    diagnosticLogBuilder.resultMessage("Token is expired.");
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                // token is not active. we do not need to worry about other details.
                introResp.setActive(false);
                return introResp;
            }

            // should be in seconds
            if (accessTokenDO.getValidityPeriodInMillis() < 0) {
                introResp.setExp(Long.MAX_VALUE);
            } else {
                if (accessTokenDO.getValidityPeriodInMillis() + accessTokenDO.getIssuedTime().getTime() < 0) {
                    // When the access token have a long validity period (eg: 9223372036854775000), the calculated
                    // expiry time will be a negative value. The reason is that, max value of long data type of Java is
                    // "9223372036854775807". So, when the addition of the validity period and the issued time exceeds
                    // this max value, it will result in a negative value. In those instances, we set the expiry time as
                    // the max value of long data type.
                    introResp.setExp(Long.MAX_VALUE);
                } else {
                    introResp.setExp(
                            (accessTokenDO.getValidityPeriodInMillis() + accessTokenDO.getIssuedTime().getTime()) /
                                    1000);
                }
            }

            String tokenType = accessTokenDO.getTokenType();

            boolean removeUsernameFromAppTokenEnabledServerConfig = OAuthServerConfiguration.getInstance()
                    .isRemoveUsernameFromIntrospectionResponseForAppTokensEnabled();
            String appResidentTenantDomain = OAuth2Util.getTenantDomain(accessTokenDO.getAppResidentTenantId());
            if (StringUtils.isEmpty(appResidentTenantDomain)) {
                // Get user domain as app domain.
                appResidentTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            }
            String consumerKey = accessTokenDO.getConsumerKey();
            ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(consumerKey, appResidentTenantDomain);
            boolean removeUsernameFromAppTokenEnabled = OAuth2Util
                    .isAppVersionAllowed(serviceProvider.getApplicationVersion(),
                            ApplicationConstants.ApplicationVersion.APP_VERSION_V1);
            boolean isAppTokenType = StringUtils.equals(OAuthConstants.UserType.APPLICATION, tokenType);

            // should be in seconds
            introResp.setIat(accessTokenDO.getIssuedTime().getTime() / 1000);
            // Not before time will be the same as issued time.
            introResp.setNbf(accessTokenDO.getIssuedTime().getTime() / 1000);
            // token scopes
            introResp.setScope(OAuth2Util.buildScopeString((accessTokenDO.getScope())));
            // set user-name
            if (!(removeUsernameFromAppTokenEnabled || removeUsernameFromAppTokenEnabledServerConfig)
                    || !isAppTokenType) {
                introResp.setUsername(getAuthzUser(accessTokenDO));
            }
            // add client id
            introResp.setClientId(accessTokenDO.getConsumerKey());
            // Set token binding info.
            if (accessTokenDO.getTokenBinding() != null) {
                String bindingType = accessTokenDO.getTokenBinding().getBindingType();
                introResp.setBindingType(bindingType);
                introResp.setBindingReference(accessTokenDO.getTokenBinding().getBindingReference());
                if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(bindingType) &&
                        StringUtils.isNotBlank(accessTokenDO.getTokenBinding().getBindingValue())) {
                    introResp.setCnfBindingValue(accessTokenDO.getTokenBinding().getBindingValue());
                }
            }
            // add authorized user type
            if (tokenType != null) {
                introResp.setAut(accessTokenDO.getTokenType());
            }
            // adding the AccessTokenDO as a context property for further use
            messageContext.addProperty("AccessTokenDO", accessTokenDO);
            // Add authenticated user object since username attribute may not have the domain appended if the
            // subject identifier is built based in the SP config.
            introResp.setAuthorizedUser(accessTokenDO.getAuthzUser());
            // Set audience if the token is not a JWT.
            if (!OAuth2Util.isJWT(validationRequest.getAccessToken().getIdentifier())) {
                addAudienceToIntrospectionResponse(introResp, accessTokenDO);
            }
            // Add acr and auth_time
            setAcrAndAuthTimeClaims(introResp, validationRequest);
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
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                diagnosticLogBuilder.resultMessage("Invalid access delegation.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            introResp.setActive(false);
            return buildIntrospectionErrorResponse("Invalid access delegation");
        }

        // Validate scopes at app level.
        if (!tokenValidator.validateScope(messageContext)) {
            // This is redundant. But sake of readability.

            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is not null only if diagnostic logs are enabled.
                diagnosticLogBuilder.resultMessage("Scope validation failed at application level.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            introResp.setActive(false);
            if (log.isDebugEnabled()) {
                log.debug("Scope validation has failed at app level.");
            }
            return buildIntrospectionErrorResponse("Scope validation failed");
        }

        // Add requested allowed scopes to the message context.
        addAllowedScopes(messageContext, requestedAllowedScopes.toArray(new String[0]));

        // Add requested allowed scopes and validated scopes to introResp.
        if (accessTokenDO != null) {
            addScopesToIntrospectionResponse(introResp, accessTokenDO, requestedAllowedScopes.toArray(new String[0]));
        }

        // All set. mark the token active.
        introResp.setActive(true);
        return introResp;
    }

    private AuthorizationGrantCacheEntry getAuthorizationGrantCacheEntryFromCode(String authorizationCode) {

        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        return AuthorizationGrantCache.getInstance().getValueFromCacheByCode(authorizationGrantCacheKey);
    }

    private void setAcrAndAuthTimeClaims(OAuth2IntrospectionResponseDTO introResp, OAuth2TokenValidationRequestDTO validationRequest){

        // AuthorizationCode only available for authorization code grant type
        AuthorizationGrantCacheEntry authzGrantCacheEntry =
                getAuthorizationGrantCacheEntryFromCode
                        (validationRequest.getAccessToken().getIdentifier());

        // Add acr and auth_time
        introResp.setAcr(authzGrantCacheEntry.getSelectedAcrValue());
        introResp.setAuthTime(authzGrantCacheEntry.getAuthTime() / 1000);
    }

    private boolean isFragmentApp(ServiceProviderProperty[] serviceProviderProperties) {

        if (serviceProviderProperties == null) {
            return false;
        }

        return Arrays.stream(serviceProviderProperties).
                anyMatch(property -> IS_FRAGMENT_APP.equals(property.getName()) &&
                        Boolean.parseBoolean(property.getValue()));
    }

    private String getAuthzUser(AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {

        AuthenticatedUser user = accessTokenDO.getAuthzUser();

        if (user.isFederatedUser()) {
            return user.getAuthenticatedSubjectIdentifier();
        }

        String consumerKey = accessTokenDO.getConsumerKey();
        try {
            boolean buildSubjectIdentifierFromSPConfig = Boolean.parseBoolean(IdentityUtil.getProperty
                    (BUILD_FQU_FROM_SP_CONFIG));
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

        OAuth2TokenValidator tokenValidator;
        if (!StringUtils.equalsIgnoreCase(accessToken.getTokenType(), DPOP_TOKEN_TYPE) &&
                isJWTTokenValidation(accessToken.getIdentifier())) {
            /*
            If the token is a self-contained JWT based access token and the
            config EnableJWTTokenValidationDuringIntrospection is set to true
            then the jwt token validator is selected. In the default pack TokenValidator
            type 'jwt' is 'org.wso2.carbon.identity.oauth2.validators.OAuth2JWTTokenValidator'.
            */
            tokenValidator = tokenValidators.get(BEARER_TOKEN_TYPE_JWT);
        } else {
            tokenValidator = tokenValidators.get(accessToken.getTokenType());
        }

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
        long expiryTime = OAuth2Util.getAccessTokenExpireMillis(accessTokenDO, false);

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
            if (OAuth2Util.getAccessTokenExpireMillis(accessTokenDO, true) == 0) {
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

        return OAuth2ServiceComponentHolder.getInstance().getTokenProvider().getVerifiedRefreshToken(refreshToken);
    }

    private boolean isJWTTokenValidation(String tokenIdentifier) {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ENABLE_JWT_TOKEN_VALIDATION)) && isParsableJWT(
                tokenIdentifier);
    }

    private boolean isSkipValidatorForJWT(OAuth2TokenValidator tokenValidator, boolean isJWTTokenValidation) {

        return isJWTTokenValidation && BEARER_TOKEN_TYPE.equals(tokenValidator.getTokenType());
    }

    private void addAllowedScopes(OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext,
                                  String[] allowedScopes) {

        String[] scopes = oAuth2TokenValidationMessageContext.getResponseDTO().getScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, allowedScopes);
        oAuth2TokenValidationMessageContext.getResponseDTO().setScope(scopesToReturn);
    }

    private void addScopesToIntrospectionResponse(OAuth2IntrospectionResponseDTO introResp, AccessTokenDO accessTokenDO,
                                                  String[] requestedAllowedScopes) {

        String[] validatedScopes = accessTokenDO.getScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(validatedScopes, requestedAllowedScopes);
        introResp.setScope(OAuth2Util.buildScopeString((scopesToReturn)));
    }

    private void addAudienceToIntrospectionResponse(OAuth2IntrospectionResponseDTO introResp,
                                                      AccessTokenDO accessTokenDO) throws IdentityOAuth2Exception {

        String tenantDomain = null;
        try {
            int appResidentTenantId = accessTokenDO.getAppResidentTenantId();
            if (appResidentTenantId != MultitenantConstants.INVALID_TENANT_ID) {
                tenantDomain = IdentityTenantUtil.getTenantDomain(appResidentTenantId);
                OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey(),
                        tenantDomain);
                List<String> audience = OAuth2Util.getOIDCAudience(accessTokenDO.getConsumerKey(), oAuthAppDO);
                introResp.setAud(String.join(",", audience));
            }
        } catch (InvalidOAuthClientException e) {
            log.warn("Unable to set the audience in the introspection response. Failed to retrieve the " +
                    "application for client id: " + accessTokenDO.getConsumerKey() + " in tenant: " + tenantDomain);
        }
    }
}
