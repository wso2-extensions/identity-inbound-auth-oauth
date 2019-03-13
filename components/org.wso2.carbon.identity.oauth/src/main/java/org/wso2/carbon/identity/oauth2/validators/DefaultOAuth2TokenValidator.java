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

package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;

/**
 * Default OAuth2 access token validator that supports "bearer" token type.
 * However this validator does not validate scopes or access delegation.
 */
public class DefaultOAuth2TokenValidator implements OAuth2TokenValidator {

    public static final String TOKEN_TYPE = "bearer";
    private static final String ACCESS_TOKEN_DO = "AccessTokenDO";
    private static final String RESOURCE = "resource";
    private Log log = LogFactory.getLog(DefaultOAuth2TokenValidator.class);

    @Override
    public boolean validateAccessDelegation(OAuth2TokenValidationMessageContext messageContext)
            throws IdentityOAuth2Exception {

        // By default we don't validate access delegation
        return true;
    }

    /**
     * Validate scope of the access token using scope validators registered for that specific app.
     *
     * @param messageContext Message context of the token validation request
     * @return Whether validation success or not
     * @throws IdentityOAuth2Exception Exception during while validation
     */
    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        String[] scopeValidators;
        AccessTokenDO accessTokenDO = (AccessTokenDO) messageContext.getProperty(ACCESS_TOKEN_DO);

        if (accessTokenDO == null) {
            return false;
        }

        OAuthAppDO app;
        try {
            app = OAuth2Util.getAppInformationByClientId(accessTokenDO.getConsumerKey());
            scopeValidators = app.getScopeValidators();
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when getting app information for " +
                    "client id %s ", accessTokenDO.getConsumerKey()), e);
        }

        if (ArrayUtils.isEmpty(scopeValidators)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("There is no scope validator registered for %s@%s", app.getApplicationName(),
                        OAuth2Util.getTenantDomainOfOauthApp(app)));
            }
            return true;
        }

        String resource = getResourceFromMessageContext(messageContext);
        Set<OAuth2ScopeValidator> oAuth2ScopeValidators = OAuthServerConfiguration.getInstance()
                .getOAuth2ScopeValidators();
        ArrayList<String> appScopeValidators = new ArrayList<>(Arrays.asList(scopeValidators));
        for (OAuth2ScopeValidator validator : oAuth2ScopeValidators) {
            if (validator != null && appScopeValidators.contains(validator.getValidatorName())
                    && validator.canHandle(messageContext)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Validating scope of token %s using %s", accessTokenDO.getTokenId(),
                            validator.getValidatorName()));
                }
                boolean isValid = validator.validateScope(accessTokenDO, resource);
                appScopeValidators.remove(validator.getValidatorName());
                if (!isValid) {
                    return false;
                }
            }
        }
        if (!appScopeValidators.isEmpty()) {
            throw new IdentityOAuth2Exception(String.format("The scope validators %s registered for application %s@%s" +
                            " are not found in the server configuration ", StringUtils.join(appScopeValidators, ", "),
                    app.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(app)));
        }
        return true;
    }

    /**
     * Extract the resource from the access token validation request message
     *
     * @param messageContext Message context of the token validation request
     * @return resource
     */
    private String getResourceFromMessageContext(OAuth2TokenValidationMessageContext messageContext) {

        String resource = null;
        if (messageContext.getRequestDTO().getContext() != null) {
            // Iterate the array of context params to find the 'resource' context param.
            for (OAuth2TokenValidationRequestDTO.TokenValidationContextParam resourceParam :
                    messageContext.getRequestDTO().getContext()) {
                // If the context param is the resource that is being accessed
                if (resourceParam != null && RESOURCE.equals(resourceParam.getKey())) {
                    resource = resourceParam.getValue();
                    break;
                }
            }
        }
        return resource;
    }

    // For validation of token profile specific items.
    // E.g. validation of HMAC signature in HMAC token profile
    @Override
    public boolean validateAccessToken(OAuth2TokenValidationMessageContext validationReqDTO)
            throws IdentityOAuth2Exception {

        // With bearer token we don't validate anything apart from access delegation and scopes
        return true;
    }

    @Override
    public String getTokenType() {

        return "Bearer";
    }

}
