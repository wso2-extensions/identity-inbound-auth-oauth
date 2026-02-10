package org.wso2.carbon.identity.oauth.ciba.model;

import org.wso2.carbon.user.core.common.User;

/**
 * This class holds the context of the user notification.
 */
public class CibaUserNotificationContext {

    private User user;
    private String authCodeKey;
    private String bindingMessage;
    private String applicationName;

    public CibaUserNotificationContext() {

    }

    public CibaUserNotificationContext(User user, String authCodeKey, String bindingMessage,
                                       String applicationName) {

        this.user = user;
        this.authCodeKey = authCodeKey;
        this.bindingMessage = bindingMessage;
        this.applicationName = applicationName;
    }

    public User getUser() {

        return user;
    }

    public void setUser(User user) {

        this.user = user;
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

    public String getApplicationName() {

        return applicationName;
    }

    public void setApplicationName(String applicationName) {

        this.applicationName = applicationName;
    }
}
