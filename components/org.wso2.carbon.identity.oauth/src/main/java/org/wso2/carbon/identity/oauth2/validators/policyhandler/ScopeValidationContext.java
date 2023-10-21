package org.wso2.carbon.identity.oauth2.validators.policyhandler;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.List;
import java.util.Map;

/**
 * PolicyContext
 */
public class ScopeValidationContext {

    private AuthenticatedUser authenticatedUser;
    private String appId;
    private String grantType;

    private String policyId;
    private Map<String, List<String>> validatedScopesByHandler;

    /**
     * Get the authenticated user.
     *
     * @return AuthenticatedUser.
     */

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    /**
     * Set the authenticated user.
     *
     * @param authenticatedUser AuthenticatedUser.
     */
    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    /**
     * Get the application id.
     *
     * @return Application ID.
     */
    public String getAppId() {

        return appId;
    }

    /**
     * Set the application id.
     *
     * @param appId Application ID.
     */
    public void setAppId(String appId) {

        this.appId = appId;
    }

    /**
     * Get the validated scopes by handler
     *
     * @return Map of validated scopes.
     */
    public Map<String, List<String>> getValidatedScopesByHandler() {

        return validatedScopesByHandler;
    }

    /**
     * Set the validated scopes by handler.
     *
     * @param validatedScopesByHandler Map of validated scopes.
     */
    public void setValidatedScopesByHandler(Map<String, List<String>> validatedScopesByHandler) {

        this.validatedScopesByHandler = validatedScopesByHandler;
    }

    /**
     * Get the grant type.
     *
     * @return Grant type.
     */
    public String getGrantType() {

        return grantType;
    }

    /**
     * Set the grant type.
     *
     * @param grantType Grant type.
     */
    public void setGrantType(String grantType) {

        this.grantType = grantType;
    }

    /**
     * Get the policy id.
     *
     * @return Policy ID.
     */
    public String getPolicyId() {

        return policyId;
    }

    /**
     * Set the policy id.
     *
     * @param policyId Policy ID.
     */
    public void setPolicyId(String policyId) {

        this.policyId = policyId;
    }
}
