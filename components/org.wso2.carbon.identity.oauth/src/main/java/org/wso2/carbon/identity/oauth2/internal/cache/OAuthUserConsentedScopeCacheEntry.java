package org.wso2.carbon.identity.oauth2.internal.cache;

import org.wso2.carbon.identity.core.cache.CacheEntry;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;

/**
 * Cache entry for User Consented Scope.
 */
public class OAuthUserConsentedScopeCacheEntry extends CacheEntry {

    private String appID;
    private UserApplicationScopeConsentDO userApplicationScopeConsentDO;

    public OAuthUserConsentedScopeCacheEntry(String appId, UserApplicationScopeConsentDO userConsent) {

        this.appID = appId;
        this.userApplicationScopeConsentDO = userConsent;

    }

    public String getAppID() {

        return appID;
    }

    public void setAppID(String appID) {

        this.appID = appID;
    }

    public UserApplicationScopeConsentDO getUserApplicationScopeConsentDO() {

        return userApplicationScopeConsentDO;
    }

    public void setUserApplicationScopeConsentDO(UserApplicationScopeConsentDO userApplicationScopeConsentDO) {

        this.userApplicationScopeConsentDO = userApplicationScopeConsentDO;
    }
}
