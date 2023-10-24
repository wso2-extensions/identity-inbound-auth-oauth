package org.wso2.carbon.identity.oauth2.validators.validationhandler;

import java.util.List;

/**
 * ScopeValidatorPolicyHandler
 */
public interface ScopeValidationHandler {

    /**
     * Check if the handler can handle the scope validation
     *
     * @param scopeValidationContext ScopeValidationContext.
     * @return boolean
     */
    boolean canHandle(ScopeValidationContext scopeValidationContext);

    /**
     * Validate scopes.
     *
     * @param requestedScopes        Requested scopes.
     * @param appAuthorizedScopes    Authorized scopes.
     * @param scopeValidationContext ScopeValidationContext.
     * @return List of scopes.
     * @throws ScopeValidationHandlerException Error when performing the scope validation.
     */
    List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                ScopeValidationContext scopeValidationContext) throws ScopeValidationHandlerException;

    /**
     * Get policy ID.
     *
     * @return Policy ID.
     */
    String getPolicyID();

    /**
     * Get handler name.
     *
     * @return Handler name.
     */

    String getName();

}
