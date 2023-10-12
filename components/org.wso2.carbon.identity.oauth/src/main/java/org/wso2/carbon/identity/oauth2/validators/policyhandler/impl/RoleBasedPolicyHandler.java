package org.wso2.carbon.identity.oauth2.validators.policyhandler.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.PolicyContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidatorPolicyHandler;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidatorPolicyHandlerException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.NotImplementedException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * RoleBasedPolicyHandler
 */
public class RoleBasedPolicyHandler implements ScopeValidatorPolicyHandler {

    private static final Log LOG = LogFactory.getLog(DefaultOAuth2ScopeValidator.class);

    @Override
    public boolean canHandle(String policyId) {

        return getPolicyID().equals(policyId);
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> policyAuthorizedScopes,
                                       PolicyContext policyContext) throws ScopeValidatorPolicyHandlerException {

        List<String> userRoles = getUserRoles(policyContext.getAuthenticatedUser(), policyContext.getAppId());
        List<String> associatedScopes = getAssociatedScopesForRoles(userRoles,
                policyContext.getAuthenticatedUser().getTenantDomain());
        List<String> filteredScopes = policyAuthorizedScopes.stream().filter(associatedScopes::contains)
                .collect(Collectors.toList());
        return requestedScopes.stream().filter(filteredScopes::contains).collect(Collectors.toList());
    }

    private List<String> getAssociatedScopesForRoles(List<String> roles, String tenantDomain) {

        // TODO :
        return null;
    }

    private List<String> getUserRoles(AuthenticatedUser authenticatedUser, String appId) {

        // TODO : Get hybrid user roles of the user

        // TODO: Get groups of the user
        List<String> groups;
        try {
            groups = getUserGroups(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            throw new RuntimeException(e);
        }
        // TODO: Get roles of the groups

        //

        return null;
    }

    /**
     * Get the groups of the authenticated user.
     *
     * @param authenticatedUser  Authenticated user.
     * @return - Groups of the user.
     */
    private List<String> getUserGroups(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Started group fetching for scope validation.");
        }
        List<String> userGroups = new ArrayList<>();
        if (authenticatedUser.isFederatedUser()) {
            // TODO: get federated user groups | at the moment, if the user is a federated user we skip the validation
            return userGroups;
        }
        RealmService realmService = UserCoreUtil.getRealmService();
        try {
            int tenantId = OAuth2Util.getTenantId(authenticatedUser.getTenantDomain());
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            List<Group> groups =
                    ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(authenticatedUser.getUserId(),
                            null, null);
            // Exclude internal and application groups from the list.
            for (Group group : groups) {
                userGroups.add(group.getGroupName());
            }
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        } catch (UserStoreException e) {
            if (isDoGetGroupListOfUserNotImplemented(e)) {
                return userGroups;
            }
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Completed group fetching for scope validation.");
        }
        return userGroups;
    }

    /**
     * Check if the UserStoreException occurred due to the doGetGroupListOfUser method not being implemented.
     *
     * @param e UserStoreException.
     * @return true if the UserStoreException was caused by the doGetGroupListOfUser method not being implemented,
     * false otherwise.
     */
    private boolean isDoGetGroupListOfUserNotImplemented(UserStoreException e) {

        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof NotImplementedException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

        @Override
    public String getPolicyID() {

        return "RBAC";
    }

    @Override
    public String getName() {

        return "RoleBasedPolicyHandler";
    }
}
