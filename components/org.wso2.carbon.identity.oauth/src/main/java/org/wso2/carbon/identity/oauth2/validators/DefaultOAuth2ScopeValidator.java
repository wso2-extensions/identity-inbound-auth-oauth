package org.wso2.carbon.identity.oauth2.validators;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xmlsec.signature.P;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.PolicyContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidatorPolicyHandler;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidatorPolicyHandlerException;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
                tenantDomain);
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
        return getAuthorizedScopes(requestedScopes, tokenReqMessageContext.getAuthorizedUser(), appId, tenantDomain);
    }

    private List<String> getAuthorizedScopes(List<String> requestedScopes, AuthenticatedUser authenticatedUser,
                                             String appId, String tenantDomain) throws IdentityOAuth2Exception  {

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
        Map<String, List<String>> policies  = getAuthorizedScopes(appId, tenantDomain);
        if (policies == null) {
            return new ArrayList<>();
        }
        List<ScopeValidatorPolicyHandler> scopeValidatorPolicyHandlers =
                OAuthComponentServiceHolder.getInstance().getScopeValidatorPolicyHandlers();
        Map<String, List<String>> validatedScopesByHandler = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : policies.entrySet()) {
            String policyId = entry.getKey();
            List<String> authorizedScopes = entry.getValue();

            for (ScopeValidatorPolicyHandler scopeValidatorPolicyHandler : scopeValidatorPolicyHandlers) {
                if (scopeValidatorPolicyHandler.canHandle(policyId)) {
                    PolicyContext policyContext =  new PolicyContext();
                    policyContext.setAuthenticatedUser(authenticatedUser);
                    policyContext.setAppId(appId);
                    policyContext.setValidatedScopesByHandler(validatedScopesByHandler);
                    List<String> validatedScopes = null;
                    try {
                        validatedScopes = scopeValidatorPolicyHandler.validateScopes(authorizedScopes,
                                requestedScopes, policyContext);
                    } catch (ScopeValidatorPolicyHandlerException e) {
                        throw new IdentityOAuth2Exception("Error while validating policies roles from " +
                                "authorization service.", e);
                    }
                    approvedScopes.addAll(validatedScopes);
                    validatedScopesByHandler.put(scopeValidatorPolicyHandler.getName(), validatedScopes);
                }
            }
        }
        return approvedScopes;
    }

    private Map<String, List<String>> getAuthorizedScopes(String appId, String tenantDomain) {

        // TODO : get authorized scopes
        return null;
    }

    private Set<String> getRequestedOIDCScopes(String tenantDomain, List<String> requestedScopes)
            throws IdentityOAuth2Exception {

        OAuthAdminServiceImpl oAuthAdminServiceImpl = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService();
        try {
            List<String> oidcScopes =  oAuthAdminServiceImpl.getRegisteredOIDCScope(tenantDomain);
            return requestedScopes.stream().distinct().filter(oidcScopes::contains).collect(Collectors.toSet());
        } catch (IdentityOAuthAdminException e) {
            throw new RuntimeException(e);
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
