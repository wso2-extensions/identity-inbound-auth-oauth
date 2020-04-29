/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.axis2.util.JavaUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.UserType;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * This class can be used to check the scopes authorized to the user based on his roles. This implementation only
 * validates the roles defined in the IDN_OAUTH2_SCOPE table
 *
 */
public class RoleBasedScopeValidator extends OAuth2ScopeValidator {

    private static final Log log = LogFactory.getLog(RoleBasedScopeValidator.class);

    public static final String DEFAULT_SCOPE_NAME = "default";
    public static final String PRESERVED_CASE_SENSITIVE_VARIABLE = "preservedCaseSensitive";
    public static final String CHECK_ROLES_FROM_SAML_ASSERTION = "checkRolesFromSamlAssertion";

    public static final String RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION = 
            "retrieveRolesFromUserStoreForScopeValidation";
    public static final String ROLE_CLAIM = "ROLE_CLAIM";
    public static final String OAUTH_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String OAUTH_JWT_ASSERTION = "assertion";
    
    //SAML authenticator related constants
    public static final String SAML2_SSO_AUTHENTICATOR_NAME = "SAML2SSOAuthenticator";
    public static final String ROLE_CLAIM_ATTRIBUTE = "RoleClaimAttribute";
    public static final String ATTRIBUTE_VALUE_SEPARATOR = "AttributeValueSeparator";
    public static final String ROLE_ATTRIBUTE_NAME = "http://wso2.org/claims/role";
    public static final String ATTRIBUTE_VALUE_SEPARATOR_CONST = ",";
    
    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {
        // not implemented
        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        List<String> authorizedScopes = null;
        String[] requestedScopes = oAuthTokenReqMessageContext.getScope();
        if (log.isDebugEnabled()) {
            log.debug("Requested scopes :" + Arrays.toString(requestedScopes));
        }
        AuthenticatedUser authenticatedUser = oAuthTokenReqMessageContext.getAuthorizedUser();
        int tenantId = IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain());
        try {
            // Get only the scopes with default binding. These scopes are mapped to roles.
            Set<Scope> retrievedScopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO()
                    .getScopes(tenantId, Oauth2ScopeConstants.DEFAULT_SCOPE_BINDING);
            if (retrievedScopes == null || retrievedScopes.isEmpty()) {
                // if there are no scopes with default binding type, no additional validation is done.
                return true;
            }
            if (log.isDebugEnabled()) {
                log.debug("Scopes with default binding registered :" + retrievedScopes.toString());
            }

            // check if requested scope is allowed for the user
            String grantType = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
            String[] userRoles = null;
            if (log.isDebugEnabled()) {
                log.debug("Requested grant type: " + grantType);
            }

            // If GrantType is SAML20_BEARER and CHECK_ROLES_FROM_SAML_ASSERTION is true, or if GrantType is
            // JWT_BEARER and retrieveRolesFromUserStoreForScopeValidation system property is true,
            // use user roles from assertion or jwt otherwise use roles from userstore.
            String isSAML2Enabled = System.getProperty(CHECK_ROLES_FROM_SAML_ASSERTION);
            String isRetrieveRolesFromUserStoreForScopeValidation = System
                    .getProperty(RETRIEVE_ROLES_FROM_USERSTORE_FOR_SCOPE_VALIDATION);
            if (GrantType.SAML20_BEARER.toString().equals(grantType) && Boolean.parseBoolean(isSAML2Enabled)) {
                log.debug("Retrieving roles from the SAML assertion..");
                authenticatedUser.setUserStoreDomain(UserType.FEDERATED_USER_DOMAIN_PREFIX);
                oAuthTokenReqMessageContext.setAuthorizedUser(authenticatedUser);
                Assertion assertion = (Assertion) oAuthTokenReqMessageContext
                        .getProperty(OAuthConstants.OAUTH_SAML2_ASSERTION);
                userRoles = getRolesFromAssertion(assertion);
                if (log.isDebugEnabled()) {
                    log.debug("Requested grant type: " + grantType);
                }
            } else if (OAUTH_JWT_BEARER_GRANT_TYPE.equals(grantType)
                    && !(Boolean.parseBoolean(isRetrieveRolesFromUserStoreForScopeValidation))) {
                log.debug("Retrieving roles from the JWT..");
                setUserAttributes(oAuthTokenReqMessageContext);
                AuthenticatedUser user = oAuthTokenReqMessageContext.getAuthorizedUser();
                Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
                if (oAuthTokenReqMessageContext.getProperty(ROLE_CLAIM) != null) {
                    userRoles = getRolesFromUserAttribute(userAttributes,
                            oAuthTokenReqMessageContext.getProperty(ROLE_CLAIM).toString());
                }
            } else {
                userRoles = getUserRoles(authenticatedUser);
            }
            if (log.isDebugEnabled()) {
                log.debug("Roles allowed for the user " + oAuthTokenReqMessageContext.getAuthorizedUser().toString()
                        + " : " + Arrays.toString(userRoles));
            }
            Map<String, String> scopeToRolesMap = getScopeToRolesMap(retrievedScopes);
            if (log.isDebugEnabled()) {
                log.debug("Scope to role mapping : " + (scopeToRolesMap == null ? "{}" : scopeToRolesMap.toString()));
            }
            
            //Get the authorized scopes for the user. user is authorized to have any scopes which are not registered as 
            //DEFAULT type scope. Scopes that are registered will be validated against the user's roles and remove them
            //if not authorized
            authorizedScopes = getAuthorizedScopes(userRoles, requestedScopes, scopeToRolesMap);
            Set<String> authorizedAllScopes = new HashSet<>();
            //To remove duplicates
            authorizedAllScopes.addAll(authorizedScopes);
            if (log.isDebugEnabled()) {
                log.debug("Authorized scopes after validation: "
                        + (authorizedAllScopes == null ? "[]" : authorizedAllScopes.toString()));
            }
            oAuthTokenReqMessageContext.setScope(authorizedAllScopes.toArray(new String[authorizedAllScopes.size()]));
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving scopes with default bind type.");
        }

        return false;
    }

    /**
     * Get scopes to roles mapping using the scopes set.
     * 
     * @param scopes Scope set
     * @return Map of scopes to role mapping. key being the scope and value being the comma separated roles.
     */
    private Map<String, String> getScopeToRolesMap(Set<Scope> scopes) {
        Map<String, String> scopesMap = new HashMap<String, String>();
        for (Scope scope : scopes) {
            List<ScopeBinding> bindings = scope.getScopeBindings();
            List<String> roleList = new ArrayList<String>();
            boolean hasDefaultBinding = false;
            for (ScopeBinding binding : bindings) {
                if (Oauth2ScopeConstants.DEFAULT_SCOPE_BINDING.equals(binding.getBindingType())) {
                    List<String> bindingRoleList = binding.getBindings();
                    String bindingRoles = StringUtils.join(bindingRoleList.toArray(new String[bindingRoleList.size()]),
                            ",");
                    roleList.add(bindingRoles);
                    hasDefaultBinding = true;
                }
            }
            if (hasDefaultBinding) {
                String roles = StringUtils.join(roleList.toArray(new String[roleList.size()]), ",");
                scopesMap.put(scope.getName(), roles);
            }
        }

        return scopesMap;
    }

    /**
     * This method is used to get authorized scopes for user from the requested scopes based on roles.
     *
     * @param userRoles Roles list of user
     * @param requestedScopes Requested scopes
     * @param scopeToRoles Scopes to role map
     * @return authorized scopes list
     */
    private List<String> getAuthorizedScopes(String[] userRoles, String[] requestedScopes,
            Map<String, String> scopeToRoles) {

        List<String> defaultScope = new ArrayList<>();

        if (userRoles == null || userRoles.length == 0) {
            userRoles = new String[0];
        }

        List<String> authorizedScopes = new ArrayList<>();
        String preservedCaseSensitiveValue = System.getProperty(PRESERVED_CASE_SENSITIVE_VARIABLE);
        boolean preservedCaseSensitive = JavaUtils.isTrueExplicitly(preservedCaseSensitiveValue);
        List<String> userRoleList;
        if (preservedCaseSensitive) {
            userRoleList = Arrays.asList(userRoles);
        } else {
            userRoleList = new ArrayList<>();
            for (String aRole : userRoles) {
                userRoleList.add(aRole.toLowerCase());
            }
        }

        // Iterate the requested scopes list.
        for (String scope : requestedScopes) {

            // If requested scope is not in the binding scope list, we ignore validation for this and set it as a valid
            // scope. This is done to keep the IS default behavior of sending back the requested scope.
            if (!scopeToRoles.containsKey(scope)) {
                authorizedScopes.add(scope);
            }

            // Get the set of roles associated with the requested scope.
            String roles = scopeToRoles.get(scope);
            // If the scope has been defined in the context of the App and if roles have been defined for the scope
            if (roles != null && roles.length() != 0) {
                List<String> roleList = new ArrayList<>();
                for (String aRole : roles.split(",")) {
                    if (preservedCaseSensitive) {
                        roleList.add(aRole.trim());
                    } else {
                        roleList.add(aRole.trim().toLowerCase());
                    }
                }
                // Check if user has at least one of the roles associated with the scope
                roleList.retainAll(userRoleList);
                if (!roleList.isEmpty()) {
                    authorizedScopes.add(scope);
                }
            } else if (scopeToRoles.containsKey(scope)) {
                // The requested scope is defined but no roles have been associated with the scope
                authorizedScopes.add(scope);
            }
        }
        return (!authorizedScopes.isEmpty()) ? authorizedScopes : defaultScope;
    }

    /**
     * Extract the roles from the user attributes.
     *
     * @param userAttributes retrieved from the token
     * @return roles
     */
    private String[] getRolesFromUserAttribute(Map<ClaimMapping, String> userAttributes, String roleClaim) {

        for (Iterator<Map.Entry<ClaimMapping, String>> iterator = userAttributes.entrySet().iterator(); iterator
                .hasNext();) {
            Map.Entry<ClaimMapping, String> entry = iterator.next();
            if (roleClaim.equals(entry.getKey().getLocalClaim().getClaimUri())
                    && StringUtils.isNotBlank(entry.getValue())) {
                return entry.getValue().replace("\\/", "/").replace("[", "").replace("]", "").replace("\"", "")
                        .split(FrameworkUtils.getMultiAttributeSeparator());
            }
        }
        return null;
    }

    /**
     * Get roles from assertion. These roles are taken from the AttributeStatements section in the SAML assertion. It 
     * reads attribute value as the role for attribute's name which is equal to the pre-defined role claim. 
     *
     * @param assertion Assertion
     * @return String[] array of roles extracted from the assertion
     */
    private String[] getRolesFromAssertion(Assertion assertion) {
        List<String> roles = new ArrayList<String>();
        String roleClaim = getRoleClaim();
        List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

        if (attributeStatementList != null) {
            for (AttributeStatement statement : attributeStatementList) {
                List<Attribute> attributesList = statement.getAttributes();
                for (Attribute attribute : attributesList) {
                    String attributeName = attribute.getName();
                    if (attributeName != null && roleClaim.equals(attributeName)) {
                        List<XMLObject> attributeValues = attribute.getAttributeValues();
                        if (attributeValues != null && attributeValues.size() == 1) {
                            String attributeValueString = getAttributeValue(attributeValues.get(0));
                            String multiAttributeSeparator = getAttributeSeparator();
                            String[] attributeValuesArray = attributeValueString.split(multiAttributeSeparator);
                            if (log.isDebugEnabled()) {
                                log.debug("Adding attributes for Assertion: " + assertion + " AttributeName : "
                                        + attributeName + ", AttributeValue : "
                                        + Arrays.toString(attributeValuesArray));
                            }
                            roles.addAll(Arrays.asList(attributeValuesArray));
                        } else if (attributeValues != null && attributeValues.size() > 1) {
                            for (XMLObject attributeValue : attributeValues) {
                                String attributeValueString = getAttributeValue(attributeValue);
                                if (log.isDebugEnabled()) {
                                    log.debug("Adding attributes for Assertion: " + assertion + " AttributeName : "
                                            + attributeName + ", AttributeValue : " + attributeValue);
                                }
                                roles.add(attributeValueString);
                            }
                        }
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Role list found for assertion: " + assertion + ", roles: " + roles);
        }
        return roles.toArray(new String[roles.size()]);
    }

    /**
     * Get attribute separator from configuration or from the constants. This checks for 'AttributeValueSeparator' 
     * property in the SAML2SSOAuthenticator authenticator in the authenticators.xml file. If not found, use a 
     * pre-defined constant
     *
     * @return string attribute separator constant
     */
    private String getAttributeSeparator() {
        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(SAML2_SSO_AUTHENTICATOR_NAME);

        if (authenticatorConfig != null) {
            Map<String, String> configParameters = authenticatorConfig.getParameters();
            if (configParameters.containsKey(ATTRIBUTE_VALUE_SEPARATOR)) {
                return configParameters.get(ATTRIBUTE_VALUE_SEPARATOR);
            }
        }
        return ATTRIBUTE_VALUE_SEPARATOR_CONST;
    }

    /**
     * Role claim attribute value from configuration file or from constants. This checks for 'RoleClaimAttribute' 
     * property in the SAML2SSOAuthenticator authenticator in the authenticators.xml file. If not found, use a 
     * pre-defined constant
     *
     * @return string role attribute name used for the authenticator.
     */
    private String getRoleClaim() {
        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(SAML2_SSO_AUTHENTICATOR_NAME);

        if (authenticatorConfig != null) {
            Map<String, String> configParameters = authenticatorConfig.getParameters();
            if (configParameters.containsKey(ROLE_CLAIM_ATTRIBUTE)) {
                return configParameters.get(ROLE_CLAIM_ATTRIBUTE);
            }
        }
        return ROLE_ATTRIBUTE_NAME;
    }

    private String getAttributeValue(XMLObject attributeValue) {
        if (attributeValue == null) {
            return null;
        } else if (attributeValue instanceof XSString) {
            return ((XSString) attributeValue).getValue();
        } else if (attributeValue instanceof XSAnyImpl) {
            return ((XSAnyImpl) attributeValue).getTextContent();
        } else {
            return attributeValue.toString();
        }
    }

    /**
     * This method is used to get roles list of the user.
     *
     * @param authenticatedUser Authenticated user
     * @return roles list
     */
    private String[] getUserRoles(AuthenticatedUser authenticatedUser) {

        String[] userRoles = null;
        String tenantDomain;
        String username;
        if (authenticatedUser.isFederatedUser()) {
            tenantDomain = MultitenantUtils.getTenantDomain(authenticatedUser.getAuthenticatedSubjectIdentifier());
            username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.getAuthenticatedSubjectIdentifier());
        } else {
            tenantDomain = authenticatedUser.getTenantDomain();
            username = authenticatedUser.getUserName();
        }
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            // If tenant Id is not set in the tokenReqContext, deriving it from username.
            if (tenantId == 0 || tenantId == -1) {
                tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            }
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            String endUsernameWithDomain = UserCoreUtil.addDomainToName(username, userStoreDomain);
            userRoles = userStoreManager.getRoleListOfUser(endUsernameWithDomain);

        } catch (UserStoreException e) {
            // Log and return since we do not want to stop issuing the token in case of scope validation failures.
            log.error("Error when getting the tenant's UserStoreManager or when getting roles of user ", e);
        }
        return userRoles;
    }
    
    
    /**
     * Extract the user roles from the JWT.
     * @param tokReqMsgCtx
     */
    private void setUserAttributes(OAuthTokenReqMessageContext tokReqMsgCtx) {
        SignedJWT signedJWT = null;
        JWTClaimsSet claimsSet = null;
        String[] roles = null;
        IdentityProvider identityProvider = null;
        try {
            signedJWT = getSignedJWT(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            log.error("Couldn't retrieve signed JWT", e);
        }
        claimsSet = getClaimSet(signedJWT);
        String jwtIssuer = claimsSet != null ? claimsSet.getIssuer() : null;
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();

        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
            if (identityProvider != null) {
                if (StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(), "default")) {
                    identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);
                    if (identityProvider == null) {
                        log.error("No Registered IDP found for the JWT with issuer name : " + jwtIssuer);
                    }
                }
            } else {
                log.error("No Registered IDP found for the JWT with issuer name : " + jwtIssuer);
            }
        } catch (IdentityProviderManagementException | IdentityOAuth2Exception e) {
            log.error("Couldn't initiate identity provider instance", e);
        }

        try {
            roles = claimsSet != null
                    ? claimsSet.getStringArrayClaim(identityProvider.getClaimConfig().getRoleClaimURI())
                    : null;
        } catch (ParseException e) {
            log.error("Couldn't retrieve roles:", e);
        }

        List<String> updatedRoles = new ArrayList<>();
        if (roles != null) {
            for (String role : roles) {
                String updatedRoleClaimValue = getUpdatedRoleClaimValue(identityProvider, role);
                if (updatedRoleClaimValue != null) {
                    updatedRoles.add(updatedRoleClaimValue);
                } else {
                    updatedRoles.add(role);
                }
            }
        }
        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        String roleClaim = identityProvider.getClaimConfig().getRoleClaimURI();
        if (roleClaim != null) {
            userAttributes.put(ClaimMapping.build(roleClaim, roleClaim, null, false),
                    updatedRoles.toString().replace(" ", ""));
            tokReqMsgCtx.addProperty(ROLE_CLAIM, roleClaim);
        }
        user.setUserAttributes(userAttributes);
        tokReqMsgCtx.setAuthorizedUser(user);
    }
    
    private IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer)
            throws IdentityOAuth2Exception {
        String issuer = "";

        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException var7) {
            String errorMsg = String.format("Error while getting Resident Identity Provider of '%s' tenant.",
                    tenantDomain);
            throw new IdentityOAuth2Exception(errorMsg, var7);
        }

        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig = IdentityApplicationManagementUtil
                .getFederatedAuthenticator(fedAuthnConfigs, "openidconnect");
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil
                    .getProperty(oauthAuthenticatorConfig.getProperties(), "IdPEntityId").getValue();
        }

        return jwtIssuer.equals(issuer) ? residentIdentityProvider : null;
    }
    
    /**
     * Method to retrieve claims from the JWT
     * @param signedJWT JWT token
     * @return JWTClaimsSet Object
     */
    private JWTClaimsSet getClaimSet(SignedJWT signedJWT) {
        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Error when trying to retrieve claimsSet from the JWT:", e);
        }
        return claimsSet;
    }

    /**
     * Method to parse the assertion and retrieve the signed JWT
     * @param tokReqMsgCtx request
     * @return SignedJWT object
     * @throws IdentityOAuth2Exception exception thrown due to a parsing error
     */
    private SignedJWT getSignedJWT(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String assertion = null;
        SignedJWT signedJWT;
        for (RequestParameter param : params) {
            if (param.getKey().equals(OAUTH_JWT_ASSERTION)) {
                assertion = param.getValue()[0];
                break;
            }
        }
        if (StringUtils.isEmpty(assertion)) {
            String errorMessage = "Error while retrieving assertion";
            throw new IdentityOAuth2Exception(errorMessage);
        }

        try {
            signedJWT = SignedJWT.parse(assertion);
            if (log.isDebugEnabled()) {
                log.debug(signedJWT);
            }
        } catch (ParseException e) {
            String errorMessage = "Error while parsing the JWT.";
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return signedJWT;
    }
    
    /**
     * Check the retrieved roles against the role mappings in the IDP and return the updated roles
     * @param identityProvider used to retrieve the role mappings
     * @param currentRoleClaimValue current roles received through the token
     * @return updated roles
     */
    private String getUpdatedRoleClaimValue(IdentityProvider identityProvider, String currentRoleClaimValue) {

        if (StringUtils.equalsIgnoreCase(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME,
                identityProvider.getIdentityProviderName())) {
            return currentRoleClaimValue;
        }
        currentRoleClaimValue = currentRoleClaimValue.replace("\\/", "/").replace("[", "").replace("]", "")
                .replace("\"", "");

        PermissionsAndRoleConfig permissionAndRoleConfig = identityProvider.getPermissionAndRoleConfig();
        if (permissionAndRoleConfig != null && ArrayUtils.isNotEmpty(permissionAndRoleConfig.getRoleMappings())) {
            String[] receivedRoles = currentRoleClaimValue.split(FrameworkUtils.getMultiAttributeSeparator());
            List<String> updatedRoleClaimValues = new ArrayList<>();
            loop: for (String receivedRole : receivedRoles) {
                for (RoleMapping roleMapping : permissionAndRoleConfig.getRoleMappings()) {
                    if (roleMapping.getRemoteRole().equals(receivedRole)) {
                        updatedRoleClaimValues.add(roleMapping.getLocalRole().getLocalRoleName());
                        continue loop;
                    }
                }
                if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
                    updatedRoleClaimValues.add(receivedRole);
                }
            }
            if (!updatedRoleClaimValues.isEmpty()) {
                return StringUtils.join(updatedRoleClaimValues, FrameworkUtils.getMultiAttributeSeparator());
            }
            return null;
        }
        if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
            return currentRoleClaimValue;
        }
        return null;
    }

}
