package org.wso2.carbon.identity.oauth2.validators.policyhandler;

import java.util.List;

/**
 * ScopeValidatorPolicyHandler
 */
public interface ScopeValidationHandler {

    boolean canHandle(ScopeValidationContext scopeValidationContext);
    List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                ScopeValidationContext scopeValidationContext) throws ScopeValidationHandlerException;
    String getPolicyID();

    String getName();

}
