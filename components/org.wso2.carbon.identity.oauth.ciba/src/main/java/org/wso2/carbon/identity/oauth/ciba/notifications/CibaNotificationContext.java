package org.wso2.carbon.identity.oauth.ciba.notifications;

import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;

/**
 * Context object containing data required for sending CIBA notifications.
 */
public class CibaNotificationContext {

    private final CibaUserResolver.ResolvedUser resolvedUser;
    private final long expiryTime;
    private final String authUrl;
    private final String bindingMessage;
    private final String tenantDomain;

    private CibaNotificationContext(CibaUserResolver.ResolvedUser resolvedUser, long expiryTime,
                                  String authUrl, String bindingMessage, String tenantDomain) {
        this.resolvedUser = resolvedUser;
        this.expiryTime = expiryTime;
        this.authUrl = authUrl;
        this.bindingMessage = bindingMessage;
        this.tenantDomain = tenantDomain;
    }

    public CibaUserResolver.ResolvedUser getResolvedUser() {

        return resolvedUser;
    }

    public long getExpiryTime() {

        return expiryTime;
    }

    public String getAuthUrl() {

        return authUrl;
    }

    public String getBindingMessage() {

        return bindingMessage;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }


    /**
     * Builder for CibaNotificationContext.
     */
    public static class Builder {

        private CibaUserResolver.ResolvedUser resolvedUser;
        private long expiryTime;
        private String authUrl;
        private String bindingMessage;
        private String tenantDomain;

        public Builder setResolvedUser(CibaUserResolver.ResolvedUser resolvedUser) {
            this.resolvedUser = resolvedUser;
            return this;
        }

        public Builder setExpiryTime(long expiryTime) {
            this.expiryTime = expiryTime;
            return this;
        }

        public Builder setAuthUrl(String authUrl) {
            this.authUrl = authUrl;
            return this;
        }

        public Builder setBindingMessage(String bindingMessage) {
            this.bindingMessage = bindingMessage;
            return this;
        }

        public Builder setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }

        public CibaNotificationContext build() {

            return new CibaNotificationContext(resolvedUser, expiryTime, authUrl, bindingMessage, tenantDomain);
        }
    }
}
