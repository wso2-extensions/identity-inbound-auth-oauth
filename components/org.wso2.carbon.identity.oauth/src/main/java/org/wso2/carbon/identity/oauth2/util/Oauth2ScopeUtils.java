/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class Oauth2ScopeUtils {

    private static final Log log = LogFactory.getLog(Oauth2ScopeUtils.class);
    public static final String OAUTH_APP_DO_PROPERTY_NAME = "OAuthAppDO";

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                error, String data)
            throws IdentityOAuth2ScopeServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), errorDescription);
    }

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                     error, String data, Throwable e)
            throws IdentityOAuth2ScopeServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), errorDescription, e);
    }

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                   error, Throwable e)
            throws IdentityOAuth2ScopeServerException {

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), error.getMessage(), e);
    }

    public static IdentityOAuth2ScopeClientException generateClientException(Oauth2ScopeConstants.ErrorMessages
                                                                                error, String data)
            throws IdentityOAuth2ScopeClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(IdentityOAuth2ScopeClientException.class, error.getCode(), errorDescription);
    }

    public static IdentityOAuth2ScopeClientException generateClientException(Oauth2ScopeConstants.ErrorMessages error,
                                                                             String data,
                                                                             Throwable e)
            throws IdentityOAuth2ScopeClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(IdentityOAuth2ScopeClientException.class, error.getCode(), errorDescription, e);
    }

    public static int getTenantID() {
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    /**
     * Validate the scopes in the request using application scope validators.
     *
     * @param tokenReqMsgContext     If a token request, can pass an OAuthTokenReqMessageContext object.
     * @param authzReqMessageContext If an authorization request, can pass an OAuthAuthzReqMessageContext object.
     * @return TRUE if the validation successful, FALSE otherwise.
     * @throws IdentityOAuth2Exception
     */
    public static boolean validateByApplicationScopeValidator(OAuthTokenReqMessageContext tokenReqMsgContext,
                                                               OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        String[] scopeValidators;
        OAuthAppDO oAuthAppDO;

        if (isATokenRequest(tokenReqMsgContext)) {
            oAuthAppDO = getOAuthAppDO(tokenReqMsgContext);
        } else {
            oAuthAppDO = getOAuthAppDO(authzReqMessageContext);
        }

        scopeValidators = oAuthAppDO.getScopeValidators();

        if (ArrayUtils.isEmpty(scopeValidators)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("There is no scope validator registered for %s@%s",
                        oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
            }
            return true;
        }

        List<String> appScopeValidators = new ArrayList<>(Arrays.asList(scopeValidators));
        // Return false only if iterateOAuth2ScopeValidators returned false. One more validation to do if it was true.
        if (isATokenRequest(tokenReqMsgContext)) {
            if (hasScopeValidationFailed(tokenReqMsgContext, appScopeValidators, null)) {
                return false;
            }
        } else {
            if (hasScopeValidationFailed(null, appScopeValidators, authzReqMessageContext)) {
                return false;
            }
        }

        if (!appScopeValidators.isEmpty()) {
            throw new IdentityOAuth2Exception(String.format("The scope validators %s registered for application " +
                    "%s@%s are not found in the server configuration ", StringUtils.join(appScopeValidators,
                    ", "), oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
        }
        return true;
    }

    private static boolean isATokenRequest(OAuthTokenReqMessageContext tokenReqMsgContext) {

        return tokenReqMsgContext != null;
    }

    private static OAuthAppDO getOAuthAppDO(OAuthTokenReqMessageContext tokenReqMsgContext) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO =
                (OAuthAppDO) tokenReqMsgContext.getProperty(OAUTH_APP_DO_PROPERTY_NAME);

        if (oAuthAppDO == null) {
            try {
                if (tokenReqMsgContext.getOauth2AccessTokenReqDTO() != null) {
                    throw new IdentityOAuth2Exception("OAuth2 Access Token Request Object was null when obtaining" +
                            " OAuth Application.");
                } else {
                    oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                            tokenReqMsgContext.getOauth2AccessTokenReqDTO().getClientId());
                }
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " +
                        tokenReqMsgContext.getOauth2AccessTokenReqDTO().getClientId(), e);
            }
        }
        return oAuthAppDO;
    }

    private static OAuthAppDO getOAuthAppDO(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO =
                (OAuthAppDO) authzReqMessageContext.getProperty(OAUTH_APP_DO_PROPERTY_NAME);

        if (oAuthAppDO == null) {
            try {
                if (authzReqMessageContext.getAuthorizationReqDTO() != null) {
                    throw new IdentityOAuth2Exception("Authorization Request Object was null when obtaining" +
                            " OAuth Application.");
                } else {
                    oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                            authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
                }
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " +
                        authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey(), e);
            }
        }
        return oAuthAppDO;
    }

    /**
     * Inverting iterateOAuth2ScopeValidators method for better readability.
     */
    private static boolean hasScopeValidationFailed(OAuthTokenReqMessageContext tokenReqMsgContext,
                                                    List<String> appScopeValidators,
                                                    OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        return !iterateOAuth2ScopeValidators(authzReqMessageContext, tokenReqMsgContext, appScopeValidators);
    }

    /**
     * Iterate through the set of OAuth2ScopeValidators and validate the scopes in the request, considering only the
     * validators added in the OAuth App.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext object. tokenReqMsgContext should be null.
     * @param tokenReqMsgContext     OAuthTokenReqMessageContext object. authzReqMessageContext should be null.
     * @param appScopeValidators     Validators to be considered.
     * @return True if scopes are valid according to all the validators sent, false otherwise.
     * @throws IdentityOAuth2Exception
     */
    private static boolean iterateOAuth2ScopeValidators(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                        OAuthTokenReqMessageContext tokenReqMsgContext,
                                                        List<String> appScopeValidators)
            throws IdentityOAuth2Exception {

        Set<OAuth2ScopeValidator> oAuth2ScopeValidators = OAuthServerConfiguration.getInstance()
                .getOAuth2ScopeValidators();
        // Iterate through all available scope validators.
        for (OAuth2ScopeValidator validator : oAuth2ScopeValidators) {
            // Validate the scopes from the validator only if it's configured in the OAuth app.
            if (validator != null && appScopeValidators.contains(validator.getValidatorName())) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Validating scope of token request using %s",
                            validator.getValidatorName()));
                }
                boolean isValid;
                try {
                    if (authzReqMessageContext != null) {
                        isValid = validator.validateScope(authzReqMessageContext);
                    } else {
                        isValid = validator.validateScope(tokenReqMsgContext);
                    }
                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Error while validating scopes from application scope " +
                            "validator", e);
                }
                appScopeValidators.remove(validator.getValidatorName());
                if (!isValid) {
                    return false;
                }
            }
        }
        return true;
    }
}
