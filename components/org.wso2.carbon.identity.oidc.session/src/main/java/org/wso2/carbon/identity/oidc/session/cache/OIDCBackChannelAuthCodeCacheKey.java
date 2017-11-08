package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.common.cache.CacheKey;

/**
 * This class holds the cache key which is AuthorizationCode
 */
public class OIDCBackChannelAuthCodeCacheKey extends CacheKey {

    private static final long serialVersionUID = 6918877910029168583L;
    private String authCode;

    /**
     * @param authCode is the cache key
     */
    public OIDCBackChannelAuthCodeCacheKey(String authCode) {

        this.authCode = authCode;
    }

    public String getAuthCode() {

        return authCode;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof OIDCBackChannelAuthCodeCacheKey)) {
            return false;
        }
        return this.authCode.equals(((OIDCBackChannelAuthCodeCacheKey) o).getAuthCode());

    }

    @Override
    public int hashCode() {

        return authCode.hashCode();
    }
}
