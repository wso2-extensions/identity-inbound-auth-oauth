package org.wso2.carbon.identity.discovery;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Utility to handle OIDC Discovery related functionality.
 */
public class DiscoveryUtil {

    public static final String OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY = "OAuth" +
            ".UseEntityIdAsIssuerInOidcDiscovery";

    /**
     * Resident Idp entity id is honoured as the OIDC issuer location based on the configuration. This addresses
     * the issue <a href="http://google.com">https://github.com/wso2/product-is/issues/4277</a>.
     */
    public static boolean isUseEntityIdAsIssuerInOidcDiscovery() {

        String useEntityIdAsIssuerInDiscovery =
                IdentityUtil.getProperty(OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY);
        if (StringUtils.isEmpty(useEntityIdAsIssuerInDiscovery)) {
            return false;
        }
        return Boolean.parseBoolean(useEntityIdAsIssuerInDiscovery);
    }
}
