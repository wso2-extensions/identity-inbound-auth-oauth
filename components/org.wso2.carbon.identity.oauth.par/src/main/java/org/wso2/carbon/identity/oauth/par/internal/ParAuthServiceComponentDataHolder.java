package org.wso2.carbon.identity.oauth.par.internal;

import org.wso2.carbon.identity.oauth.par.core.ParAuthService;

/**
 * Data holder class for the PAR component
 */
public class ParAuthServiceComponentDataHolder {

    private static final ParAuthServiceComponentDataHolder instance = new ParAuthServiceComponentDataHolder();
    private ParAuthService parAuthService;

    public static ParAuthServiceComponentDataHolder getInstance() {

        return instance;
    }

    /**
     * Set ParAuthService.
     *
     * @param parAuthService ParAuthService.
     */
    public void setParAuthService(ParAuthService parAuthService) {

        this.parAuthService = parAuthService;
    }

    /**
     * Get ParAuthService.
     *
     * @return ParAuthService.
     */
    public ParAuthService getParAuthService() {

        return parAuthService;
    }
}
