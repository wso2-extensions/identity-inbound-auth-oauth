package org.wso2.carbon.identity.oauth2.validators.policyhandler;

import java.util.List;

public interface ScopeValidatorPolicyHandler {

    boolean canHandle(String policyId);
    List<String> validateScopes(List<String> requestedScopes, List<String> policyAuthorizedScopes,
                                PolicyContext policyContext) throws ScopeValidatorPolicyHandlerException;
    String getPolicyID();

    String getName();

}
