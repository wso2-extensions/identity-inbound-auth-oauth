package org.wso2.carbon.identity.oauth2.validators.validationhandler.impl;

import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerException;

import java.util.List;
import java.util.stream.Collectors;

/**
 * NoPolicyPolicyHandler
 */
public class NoPolicyScopeValidationHandler implements ScopeValidationHandler {

    @Override
    public boolean canHandle(ScopeValidationContext scopeValidationContext) {

        return getPolicyID().equals(scopeValidationContext.getPolicyId());
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                       ScopeValidationContext scopeValidationContext)
            throws ScopeValidationHandlerException {

        return requestedScopes.stream().filter(appAuthorizedScopes::contains).collect(Collectors.toList());
    }

    @Override
    public String getPolicyID() {

        return "NO POLICY";
    }

    @Override
    public String getName() {

        return "NoPolicyScopeValidationHandler";
    }
}
