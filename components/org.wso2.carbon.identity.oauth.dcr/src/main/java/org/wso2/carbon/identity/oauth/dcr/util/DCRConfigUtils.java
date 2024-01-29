/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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

        String enableDCRFapiValue = IdentityUtil.getProperty(OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT);
        Boolean enableDCRFapi = enableDCRFapiValue != null ? Boolean.parseBoolean(enableDCRFapiValue) : null;

        String clientAuthenticationRequiredValue = IdentityUtil.getProperty(
                OAuthConstants.DCR_CLIENT_AUTHENTICATION_REQUIRED);
        Boolean clientAuthenticationRequired = clientAuthenticationRequiredValue != null ?
                Boolean.parseBoolean(clientAuthenticationRequiredValue) : null;

        String ssaJwks = IdentityUtil.getProperty(OAuthConstants.DCR_SSA_VALIDATION_JWKS);

        dcrConfiguration.setFAPIEnforced(enableDCRFapi);
        dcrConfiguration.setClientAuthenticationRequired(clientAuthenticationRequired);
        dcrConfiguration.setSsaJwks(ssaJwks);

        return dcrConfiguration;
    }

    /**
     * Override the server configuration with resource values.
     *
     * @param resource Resource
     * @return DCRConfiguration Configuration instance.
     */
    public static DCRConfiguration overrideConfigsWithResource(Resource resource, DCRConfiguration dcrConfiguration) {

        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);

            String enableDCRFapiValue = attributeMap.get(ENABLE_FAPI_ENFORCEMENT);
            Boolean enableDCRFapi = enableDCRFapiValue != null ? Boolean.parseBoolean(enableDCRFapiValue) : null;

            String clientAuthenticationRequiredValue = attributeMap.get(CLIENT_AUTHENTICATION_REQUIRED);
            Boolean clientAuthenticationRequired = clientAuthenticationRequiredValue != null ?
                    Boolean.parseBoolean(clientAuthenticationRequiredValue) : null;

            String ssaJwks = attributeMap.get(SSA_JWKS);

            if (enableDCRFapi != null) {
                dcrConfiguration.setFAPIEnforced(enableDCRFapi);
            }
            if (clientAuthenticationRequired != null) {
                dcrConfiguration.setClientAuthenticationRequired(clientAuthenticationRequired);
            }
            if (ssaJwks != null) {
                dcrConfiguration.setSsaJwks(ssaJwks);
            }
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
