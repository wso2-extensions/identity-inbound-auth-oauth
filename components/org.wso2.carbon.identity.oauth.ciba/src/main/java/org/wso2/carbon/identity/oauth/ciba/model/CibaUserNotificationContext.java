package org.wso2.carbon.identity.oauth.ciba.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

/**
 * This class holds the context of the user notification.
 */
public class CibaUserNotificationContext {

    private AuthenticatedUser authenticatedUser;
    private String authCodeKey;
    private String bindingMessage;

    public CibaUserNotificationContext() {

    }

    public CibaUserNotificationContext(AuthenticatedUser authenticatedUser, String authCodeKey, String bindingMessage) {

        this.authenticatedUser = authenticatedUser;
        this.authCodeKey = authCodeKey;
        this.bindingMessage = bindingMessage;
    }

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    public void setAuthenticatedUser(
            AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    public String getAuthCodeKey() {

        return authCodeKey;
    }

    public void setAuthCodeKey(String authCodeKey) {

        this.authCodeKey = authCodeKey;
    }

    public String getBindingMessage() {

        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {

        this.bindingMessage = bindingMessage;
    }
}
