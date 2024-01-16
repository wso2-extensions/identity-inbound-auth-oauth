package org.wso2.carbon.identity.oauth.dcr.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.CLIENT_AUTHENTICATION_REQUIRED;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.ENABLE_FAPI_ENFORCEMENT;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.SSA_JWKS;


/**
 * Util class for DCR configurations and DCR resource related operations.
 */
public class DCRConfigUtils {

    /**
     * Get the DCR configuration from the server configuration.
     *
     * @return DCRConfiguration The DCR configuration.
     */
    public static DCRConfiguration getServerConfiguration() {

        DCRConfiguration dcrConfiguration = new DCRConfiguration();

        boolean enableDCRFapi = Boolean.parseBoolean(IdentityUtil.getProperty(
                OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT));
        boolean clientAuthenticationRequired = Boolean.parseBoolean(IdentityUtil.getProperty(
                OAuthConstants.DCR_CLIENT_AUTHENTICATION_REQUIRED));
//            TODO : check if DCR_CLIENT_AUTHENTICATION_REQUIRED value is correct
        String ssaJwks = IdentityUtil.getProperty(OAuthConstants.DCR_SSA_VALIDATION_JWKS);

        dcrConfiguration.setFAPIEnforced(enableDCRFapi);
        dcrConfiguration.setClientAuthenticationRequired(clientAuthenticationRequired);
        dcrConfiguration.setSsaJwks(ssaJwks);

        return dcrConfiguration;
    }

    /**
     * Parse Resource to DCRConfiguration instance.
     *
     * @param resource Resource
     * @return DCRConfiguration Configuration instance.
     */
    public static DCRConfiguration parseResource(Resource resource) {

        DCRConfiguration dcrConfiguration = new DCRConfiguration();

        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);

            boolean enableFAPIDCR = Boolean.parseBoolean(attributeMap.get(ENABLE_FAPI_ENFORCEMENT));
            boolean clientAuthenticationRequired = Boolean.parseBoolean(attributeMap.get(
                    CLIENT_AUTHENTICATION_REQUIRED));
            String ssaJwks = attributeMap.get(SSA_JWKS);

            dcrConfiguration.setFAPIEnforced(enableFAPIDCR);
            dcrConfiguration.setClientAuthenticationRequired(clientAuthenticationRequired);
            dcrConfiguration.setSsaJwks(ssaJwks);
        }
        return dcrConfiguration;

    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }

        return Collections.emptyMap();
    }

    /**
     * Parse DCRConfiguration to Resource instance.
     *
     * @param dcrConfiguration Configuration Instance.
     * @return ResourceAdd Resource instance.
     */
    public static ResourceAdd parseConfig(DCRConfiguration dcrConfiguration) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(DCR_CONFIG_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();

        String isFAPIEnforced = String.valueOf(dcrConfiguration.isFAPIEnforced());
        String isClientAuthenticationRequired = String.valueOf(dcrConfiguration.isClientAuthenticationRequired());
        String ssaJwks = dcrConfiguration.getSsaJwks();

        addAttribute(attributes, ENABLE_FAPI_ENFORCEMENT, isFAPIEnforced);
        addAttribute(attributes, CLIENT_AUTHENTICATION_REQUIRED, isClientAuthenticationRequired);
        addAttribute(attributes, SSA_JWKS, ssaJwks);

        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }

    private static void addAttribute(List<Attribute> attributeList, String key, String value) {

        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(key);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }
}
