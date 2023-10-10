package org.wso2.carbon.identity.oauth2.validators.policyhandler.impl;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.PolicyContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidatorPolicyHandler;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidatorPolicyHandlerException;

import java.util.List;
import java.util.stream.Collectors;

public class RoleBasedPolicyHandler implements ScopeValidatorPolicyHandler {

    @Override
    public boolean canHandle(String policyId) {

        return getPolicyID().equals(policyId);
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> policyAuthorizedScopes,
                                       PolicyContext policyContext) throws ScopeValidatorPolicyHandlerException {

        return requestedScopes.stream().filter(policyAuthorizedScopes::contains).collect(Collectors.toList());
    }

    private List<String> getApplicationRoles(AuthenticatedUser authenticatedUser, String appId) {

        return null;
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
