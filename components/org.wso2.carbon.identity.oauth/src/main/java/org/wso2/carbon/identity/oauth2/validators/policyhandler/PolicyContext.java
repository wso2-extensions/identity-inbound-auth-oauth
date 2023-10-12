package org.wso2.carbon.identity.oauth2.validators.policyhandler;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.List;
import java.util.Map;

/**
 * PolicyContext
 */
public class PolicyContext {

    private AuthenticatedUser authenticatedUser;
    private String appId;
    private Map<String, List<String>> validatedScopesByHandler;

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    public String getAppId() {

        return appId;
    }

    public void setAppId(String appId) {

        this.appId = appId;
    }

    public Map<String, List<String>> getValidatedScopesByHandler() {

        return validatedScopesByHandler;
    }

    public void setValidatedScopesByHandler(Map<String, List<String>> validatedScopesByHandler) {

        this.validatedScopesByHandler = validatedScopesByHandler;
    }
}
