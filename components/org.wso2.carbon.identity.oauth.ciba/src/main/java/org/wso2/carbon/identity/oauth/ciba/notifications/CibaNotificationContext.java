package org.wso2.carbon.identity.oauth.ciba.notifications;

import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;

import java.util.Collections;
import java.util.List;

/**
 * Context object containing data required for sending CIBA notifications.
 */
public class CibaNotificationContext {

    private final CibaUserResolver.ResolvedUser resolvedUser;
    private final long expiryTime;
    private final String authUrl;
    private final String bindingMessage;
    private final String tenantDomain;
    private final String requestedChannel;
    private final List<String> appAllowedChannels;

    private CibaNotificationContext(CibaUserResolver.ResolvedUser resolvedUser, long expiryTime, String authUrl,
                                    String bindingMessage, String tenantDomain, String requestedChannel,
                                    List<String> appAllowedChannels) {

        this.resolvedUser = resolvedUser;
        this.expiryTime = expiryTime;
        this.authUrl = authUrl;
        this.bindingMessage = bindingMessage;
        this.tenantDomain = tenantDomain;
        this.requestedChannel = requestedChannel;
        this.appAllowedChannels = appAllowedChannels;
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

    public String getRequestedChannel() {

        return requestedChannel;
    }

    public List<String> getAppAllowedChannels() {

        return appAllowedChannels;
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
        private String requestedChannel;
        private List<String> appAllowedChannels;

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

        public Builder setRequestedChannel(String requestedChannel) {

            this.requestedChannel = requestedChannel;
            return this;
        }

        public Builder setAppAllowedChannels(List<String> appAllowedChannels) {

            this.appAllowedChannels = appAllowedChannels;
            return this;
        }

        public CibaNotificationContext build() {

            if (appAllowedChannels == null) {
                appAllowedChannels = Collections.emptyList();
            }
            return new CibaNotificationContext(resolvedUser, expiryTime, authUrl, bindingMessage,
                    tenantDomain, requestedChannel, appAllowedChannels);
        }
    }
}
