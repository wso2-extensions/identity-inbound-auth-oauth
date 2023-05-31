/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.validators.scope;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.saml.saml2.core.Assertion;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.multitenancy.utils.TenantAxisUtils;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getAppInformationByClientId;

/**
 * This abstract class represents the basic requirements of a scope issuer.
 */
public abstract class AbstractRoleBasedScopeIssuer {

    private static final String DEFAULT_SCOPE_NAME = "default";
    private static final Log log = LogFactory.getLog(AbstractRoleBasedScopeIssuer.class);

    /**
     * This method is used to retrieve the authorized scopes with respect to a token.
     *
     * @param tokReqMsgCtx token message context
     * @return authorized scopes list
     */
    public abstract List<String> getScopes(OAuthTokenReqMessageContext tokReqMsgCtx);

    /**
     * This method is used to retrieve authorized scopes with respect to an authorization callback.
     *
     * @param scopeValidationCallback Authorization callback to validate scopes
     * @return authorized scopes list
     */
    public abstract List<String> getScopes(OAuthCallback scopeValidationCallback);

    /**
     * This method is used to get the prefix of the scope issuer.
     *
     * @return returns the prefix with respect to an issuer.
     */
    public abstract String getPrefix();

    /**
     * Get the set of default scopes. If a requested scope is matches with the patterns specified in the whitelist,
     * then such scopes will be issued without further validation. If the scope list is empty,
     * token will be issued for default scope.
     *
     * @param requestedScopes - The set of requested scopes
     * @return - The subset of scopes that are allowed
     */
    public List<String> getAllowedScopes(List<String> requestedScopes) {

        if (requestedScopes.isEmpty()) {
            requestedScopes.add(DEFAULT_SCOPE_NAME);
        }
        return requestedScopes;
    }

    /**
     * Determines if the scope is specified in the whitelist.
     *
     * @param scope - The scope key to check
     * @return - 'true' if the scope is whitelisted. 'false' if not.
     */
    public boolean isWhiteListedScope(List<String> scopeSkipList, String scope) {

        for (String scopeTobeSkipped : scopeSkipList) {
            if (scope.matches(scopeTobeSkipped)) {
                return true;
            }
        }
        return false;
    }

    /**
     * This method is used to get the application scopes including the scopes defined for the APIs subscribed to the
     * application and the API-M REST API scopes set of the current tenant.
     *
     * @param consumerKey       Consumer Key of the application
     * @param authenticatedUser Authenticated User
     * @return Application Scope List
     */
    public Map<String, String> getAppScopes(String consumerKey, AuthenticatedUser authenticatedUser,
                                            List<String> requestedScopes) {

        //Get all the scopes and roles against the scopes defined for the APIs subscribed to the application.
        boolean isTenantFlowStarted = false;
        Map<String, String> appScopes = null;
        Set<Scope> scopes = null;
        String requestedScopesString = String.join(" ", requestedScopes);
        String tenantDomain;
        try {
            if (authenticatedUser.isFederatedUser()) {
                tenantDomain = getAppInformationByClientId(consumerKey).getAppOwner().getTenantDomain();
            } else {
                tenantDomain = authenticatedUser.getTenantDomain();
            }
            if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                isTenantFlowStarted = true;
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                loadTenantConfigBlockingMode(tenantDomain);
            }
            scopes = getOAuth2ScopeService().getScopes(null, null, true, requestedScopesString);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            log.error("Error when retrieving the tenant domain " + e.getMessage(), e);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while getting scopes " + e.getMessage(), e);
        } finally {
            if (isTenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }

        // Need to get app scopes via IS tables or service.
        if (scopes != null) {
            appScopes = getAppScopes(scopes);
        }
        return appScopes;
    }

    private Map<String, String> getAppScopes(Set<Scope> scopes) {

        Map<String, String> appScopes = new HashMap<>();
        for (Scope scope : scopes) {
            ScopeBinding scopeBinding = getScopeBinding(scope.getScopeBindings());
            String bindings = "";
            if (scopeBinding != null) {
                bindings = String.join(",", scopeBinding.getBindings());
            }

            appScopes.put(scope.getName(), bindings);
        }

        return appScopes;
    }

    private ScopeBinding getScopeBinding(List<ScopeBinding> scopeBindings) {

        for (ScopeBinding scopeBinding : scopeBindings) {
            if (OAuth2Constants.RoleBasedScope.OAUTH2_DEFAULT_SCOPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                return scopeBinding;
            }
        }
        return null;
    }

    /**
     * This method is used to check if the application scope list empty.
     *
     * @param appScopes Application scopes list
     * @param clientId  Client ID of the application
     * @return if the scopes list is empty
     */
    public boolean isAppScopesEmpty(Map<String, String> appScopes, String clientId) {

        if (appScopes.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No scopes defined for the Application " + clientId);
            }
            return true;
        }
        return false;
    }

    /**
     * Get tenant ID of the user.
     *
     * @param username Username
     * @return int
     */
    protected int getTenantIdOfUser(String username) {

        return IdentityTenantUtil.getTenantIdOfUser(username);
    }

    public OAuth2ScopeService getOAuth2ScopeService() {

        return (OAuth2ScopeService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(OAuth2ScopeService.class, null);
    }

    /**
     * Get the role list from the SAML2 Assertion.
     *
     * @param assertion SAML2 assertion
     * @return Role list from the assertion
     */
    public String[] getRolesFromAssertion(Assertion assertion) {

        String roleClaim = getRoleClaim();
        List<String> roles = assertion.getAttributeStatements().stream()
                .flatMap(statement -> statement.getAttributes().stream())
                .filter(attribute -> roleClaim.equals(attribute.getName()))
                .flatMap(attribute -> {
                    List<XMLObject> attributeValues = attribute.getAttributeValues();
                    if (attributeValues != null && attributeValues.size() == 1) {
                        String attributeValueString = getAttributeValue(attributeValues.get(0));
                        String multiAttributeSeparator = getAttributeSeparator();
                        String[] attributeValuesArray = attributeValueString.split(multiAttributeSeparator);
                        if (log.isDebugEnabled()) {
                            log.debug("Adding attributes for Assertion: " + assertion + " AttributeName : "
                                    + attribute.getName() + ", AttributeValue : "
                                    + Arrays.toString(attributeValuesArray));
                        }
                        return Arrays.stream(attributeValuesArray);
                    } else if (attributeValues != null && attributeValues.size() > 1) {
                        return attributeValues.stream()
                                .map(this::getAttributeValue)
                                .filter(Objects::nonNull);
                    } else {
                        return Stream.empty();
                    }
                })
                .collect(Collectors.toList());
        if (log.isDebugEnabled()) {
            log.debug("Role list found for assertion: " + assertion + ", roles: " + roles);
        }
        return roles.toArray(new String[0]);
    }

    private String getAttributeValue(XMLObject attributeValue) {

        if (attributeValue == null) {
            return null;
        } else if (attributeValue instanceof XSString) {
            return getStringAttributeValue((XSString) attributeValue);
        } else if (attributeValue instanceof XSAnyImpl) {
            return getAnyAttributeValue((XSAnyImpl) attributeValue);
        }
        return attributeValue.toString();
    }

    private String getStringAttributeValue(XSString attributeValue) {

        return attributeValue.getValue();
    }

    private String getAnyAttributeValue(XSAnyImpl attributeValue) {

        return attributeValue.getTextContent();
    }

    /**
     * Get attribute separator from configuration or from the constants.
     *
     * @return Attribute value separator.
     */
    private String getAttributeSeparator() {

        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(OAuth2Constants.RoleBasedScope.SAML2_SSO_AUTHENTICATOR_NAME);

        if (authenticatorConfig != null) {
            Map<String, String> configParameters = authenticatorConfig.getParameters();
            if (configParameters.containsKey(OAuth2Constants.RoleBasedScope.ATTRIBUTE_VALUE_SEPARATOR)) {
                return configParameters.get(OAuth2Constants.RoleBasedScope.ATTRIBUTE_VALUE_SEPARATOR);
            }
        }

        return OAuth2Constants.RoleBasedScope.ATTRIBUTE_VALUE_SEPERATER;
    }

    /**
     * Role claim attribute value from configuration file or from constants.
     *
     * @return role claim name.
     */
    private String getRoleClaim() {

        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(OAuth2Constants.RoleBasedScope.SAML2_SSO_AUTHENTICATOR_NAME);

        if (authenticatorConfig != null) {
            Map<String, String> configParameters = authenticatorConfig.getParameters();
            if (configParameters.containsKey(OAuth2Constants.RoleBasedScope.ROLE_CLAIM_ATTRIBUTE)) {
                return configParameters.get(OAuth2Constants.RoleBasedScope.ROLE_CLAIM_ATTRIBUTE);
            }
        }
        return OAuth2Constants.RoleBasedScope.ROLE_ATTRIBUTE_NAME;
    }

    /**
     * Load tenant axis configurations.
     *
     * @param tenantDomain Tenant domain
     */
    public static void loadTenantConfigBlockingMode(String tenantDomain) {

        try {
            ConfigurationContext ctx = OAuth2ServiceComponentHolder.getConfigurationContextService()
                    .getServerConfigContext();
            TenantAxisUtils.getTenantAxisConfiguration(tenantDomain, ctx);
        } catch (Exception e) {
            log.error("Error while creating axis configuration for tenant " + tenantDomain, e);
        }
    }
}
