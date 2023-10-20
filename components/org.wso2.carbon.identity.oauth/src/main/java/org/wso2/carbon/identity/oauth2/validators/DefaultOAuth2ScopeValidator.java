package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.api.resource.mgt.APIResourceMgtException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AuthorizedScopes;
import org.wso2.carbon.identity.application.common.model.Scope;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationHandlerException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;

/**
 * DefaultOAuth2ScopeValidator
 */
public class DefaultOAuth2ScopeValidator {

    public static final String CLIENT_TYPE = "oauth2";

    private static final Log LOG = LogFactory.getLog(DefaultOAuth2ScopeValidator.class);

    public List<String> validateScope(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (isScopesEmpty(authzReqMessageContext.getAuthorizationReqDTO().getScopes())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested scope list is empty. Therefore, default OAuth2 scope validation is skipped.");
            }
            return new ArrayList<>();
        }
        List<String> requestedScopes = Arrays.asList(authzReqMessageContext.getAuthorizationReqDTO().getScopes());
        String tenantDomain = authzReqMessageContext.getAuthorizationReqDTO().getTenantDomain();
        String clientId = authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey();
        String appId = getApplicationId(clientId, tenantDomain);
        return getAuthorizedScopes(requestedScopes, authzReqMessageContext.getAuthorizationReqDTO().getUser(), appId,
                null, tenantDomain);
    }

    public List<String> validateScope(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (isScopesEmpty(tokenReqMessageContext.getScope())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Requested scope list is empty. Therefore, default OAuth2 scope validation is skipped.");
            }
            return new ArrayList<>();
        }
        List<String> requestedScopes = Arrays.asList(tokenReqMessageContext.getScope());
        String tenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        String appId = getApplicationId(clientId, tenantDomain);
        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        return getAuthorizedScopes(requestedScopes, tokenReqMessageContext.getAuthorizedUser(), appId, grantType,
                tenantDomain);
    }

    private List<String> getAuthorizedScopes(List<String> requestedScopes, AuthenticatedUser authenticatedUser,
                                             String appId, String grantType, String tenantDomain)
            throws IdentityOAuth2Exception  {

        // Filter OIDC scopes and add to approved scopes list.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Filtering OIDC scopes from requested scopes: " + StringUtils.join(requestedScopes, " "));
        }
        Set<String> requestedOIDCScopes = getRequestedOIDCScopes(tenantDomain, requestedScopes);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Requested OIDC scopes : " + StringUtils.join(requestedOIDCScopes, " "));
        }
        /* Here, we add the user-requested OIDC scopes to the approved scope list and remove from requested scope list
        before we pass the scopes to the authorization service. Otherwise, the OIDC scopes will be dropped from
        the approved scope list. */
        List<String> approvedScopes = new ArrayList<>(requestedOIDCScopes);
        requestedScopes = removeOIDCScopes(requestedScopes, requestedOIDCScopes);
        if (requestedScopes.contains(SYSTEM_SCOPE)) {
            requestedScopes.addAll(getInternalScopes(tenantDomain));
        }
        List<AuthorizedScopes> authorizedScopesList  = getAuthorizedScopes(appId, tenantDomain);
        List<ScopeValidationHandler> scopeValidationHandlers =
                OAuthComponentServiceHolder.getInstance().getScopeValidationHandlers();
        Map<String, List<String>> validatedScopesByHandler = new HashMap<>();
        for (AuthorizedScopes authorizedScopes: authorizedScopesList) {
            String policyId = authorizedScopes.getPolicyId();
            ScopeValidationContext policyContext =  new ScopeValidationContext();
            policyContext.setAuthenticatedUser(authenticatedUser);
            policyContext.setAppId(appId);
            policyContext.setPolicyId(policyId);
            policyContext.setGrantType(grantType);
            for (ScopeValidationHandler scopeValidationHandler : scopeValidationHandlers) {
                if (scopeValidationHandler.canHandle(policyContext)) {
                    policyContext.setValidatedScopesByHandler(validatedScopesByHandler);
                    List<String> validatedScopes;
                    try {
                        validatedScopes = scopeValidationHandler.validateScopes(requestedScopes,
                                authorizedScopes.getScopes(), policyContext);
                    } catch (ScopeValidationHandlerException e) {
                        throw new IdentityOAuth2Exception("Error while validating policies roles from " +
                                "authorization service.", e);
                    }
                    validatedScopesByHandler.put(scopeValidationHandler.getName(), validatedScopes);
                }
            }
        }

        // If "NoPolicy" exists, add all its scopes to the result
        Set<String> scopes = new HashSet<>(validatedScopesByHandler.getOrDefault("NoPolicyScopeValidationHandler",
                Collections.emptyList()));

        // Separate "NoPolicy" and get the intersection of the rest of the scopes validated by other validators
        List<List<String>> otherHandlerScopes = new ArrayList<>(validatedScopesByHandler.values());
        otherHandlerScopes.remove(validatedScopesByHandler.get("NoPolicyScopeValidationHandler"));

        List<String> intersection = new ArrayList<>();
        if (!otherHandlerScopes.isEmpty()) {
            intersection = otherHandlerScopes.get(0);
            for (int i = 1; i < otherHandlerScopes.size(); i++) {
                intersection = intersection.stream().filter(otherHandlerScopes.get(i)::contains)
                        .collect(Collectors.toList());
            }
        }
        scopes.addAll(intersection);
        approvedScopes.addAll(scopes);
        return approvedScopes;
    }

    private List<AuthorizedScopes> getAuthorizedScopes(String appId, String tenantDomain)
            throws IdentityOAuth2Exception {

        try {
            return OAuth2ServiceComponentHolder.getInstance()
                    .getAuthorizedAPIManagementService().getAuthorizedScopes(appId, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving authorized scopes for app : " + appId
                    + "tenant domain : " + tenantDomain, e);
        }
    }

    private List<String> getInternalScopes(String tenantDomain) throws IdentityOAuth2Exception {

        try {
            List<Scope> scopes =  OAuth2ServiceComponentHolder.getInstance()
                    .getApiResourceManager().getScopesByTenantDomain(tenantDomain, "name sw internal_");
            return scopes.stream().map(Scope::getName).collect(Collectors.toCollection(ArrayList::new));
        } catch (APIResourceMgtException e) {
            throw new IdentityOAuth2Exception("Error while retrieving internal scopes for tenant domain : "
                    + tenantDomain, e);
        }
    }

    private Set<String> getRequestedOIDCScopes(String tenantDomain, List<String> requestedScopes)
            throws IdentityOAuth2Exception {

        OAuthAdminServiceImpl oAuthAdminServiceImpl = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService();
        try {
            List<String> oidcScopes =  oAuthAdminServiceImpl.getRegisteredOIDCScope(tenantDomain);
            return requestedScopes.stream().distinct().filter(oidcScopes::contains).collect(Collectors.toSet());
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityOAuth2Exception("Error while retrieving oidc scopes for tenant domain : "
                    + tenantDomain, e);
        }
    }

    private List<String> removeOIDCScopes(List<String> requestedScopes, Set<String> oidcScopes) {

        return requestedScopes.stream().distinct().filter(s -> !oidcScopes.contains(s)).collect(Collectors.toList());
    }

    private String getApplicationId(String clientId, String tenantName) throws IdentityOAuth2Exception {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        try {
            return applicationMgtService.getApplicationResourceIDByInboundKey(clientId, CLIENT_TYPE, tenantName);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error while retrieving application resource id for client : " +
                    clientId + " tenant : " + tenantName, e);
        }
    }

    private boolean isScopesEmpty(String[] scopes) {

        return ArrayUtils.isEmpty(scopes);
    }

}
