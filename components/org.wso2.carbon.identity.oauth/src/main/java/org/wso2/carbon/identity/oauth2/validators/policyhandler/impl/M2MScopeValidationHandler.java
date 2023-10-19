package org.wso2.carbon.identity.oauth2.validators.policyhandler.impl;

import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.policyhandler.ScopeValidationHandlerException;

import java.util.List;
import java.util.stream.Collectors;

/**
 * M2MScopeValidationHandler
 */
public class M2MScopeValidationHandler implements ScopeValidationHandler {

    @Override
    public boolean canHandle(ScopeValidationContext scopeValidationContext) {

        return OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(scopeValidationContext.getGrantType()) &&
                !getPolicyID().equals("NoPolicy");
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                       ScopeValidationContext scopeValidationContext)
            throws ScopeValidationHandlerException {

        return requestedScopes.stream().filter(appAuthorizedScopes::contains).collect(Collectors.toList());
    }

    @Override
    public String getPolicyID() {

        return null;
    }

    @Override
    public String getName() {

        return "M2MScopeValidationHandler";
    }
}
