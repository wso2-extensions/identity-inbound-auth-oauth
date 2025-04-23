/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.finegrainedauthz.utils;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.exceptions.FineGrainedAuthzConfigMgtException;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.exceptions.FineGrainedAuthzConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.models.FineGrainedAuthzConfig;
import org.wso2.carbon.identity.oauth2.impersonation.utils.ErrorMessage;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Utility class for managing fine-grained authorization configurations.
 */
public class Util {

    private static final String FINE_GRAINED_AUTHZ_RESOURCE_NAME = "TENANT_FINE_GRAINED_AUTHZ_CONFIGURATION";
    private static final String ENABLE_FINE_GRAINED_AUTHZ = "EnableFineGrainedApiAuthorization";

    public static ResourceAdd parseConfig(FineGrainedAuthzConfig fineGrainedAuthzConfig) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(FINE_GRAINED_AUTHZ_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();
        addAttribute(attributes, fineGrainedAuthzConfig);
        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }

    private static void addAttribute(List<Attribute> attributeList, FineGrainedAuthzConfig fineGrainedAuthzConfig) {

        String value = String.valueOf(fineGrainedAuthzConfig.isEnableFineGrainedAuthz());
        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(ENABLE_FINE_GRAINED_AUTHZ);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }

    public static FineGrainedAuthzConfigMgtException handleClientException(ErrorMessage error, Throwable e,
                                                                           String data) {

        return new FineGrainedAuthzConfigMgtException(String.format(error.getDescription(), data),
                error.getCode(), e);
    }

    public static FineGrainedAuthzConfigMgtException handleServerException(ErrorMessage error, Throwable e,
                                                                        String... data) {

        return new FineGrainedAuthzConfigMgtServerException(String.format(error.getDescription(), data),
                error.getCode(), e);
    }

    /*
    * Get the default configuration for fine-grained authorization.
     */
    public static FineGrainedAuthzConfig getDefaultConfiguration() {

        FineGrainedAuthzConfig fineGrainedAuthzConfig = new FineGrainedAuthzConfig();
        fineGrainedAuthzConfig.setEnableFineGrainedAuthz(false);
        return fineGrainedAuthzConfig;
    }

    public static FineGrainedAuthzConfig parseResource(Resource resource) {

        FineGrainedAuthzConfig fineGrainedAuthzConfig = new FineGrainedAuthzConfig();
        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);
            fineGrainedAuthzConfig.setEnableFineGrainedAuthz(Boolean.parseBoolean(
                    attributeMap.get(ENABLE_FINE_GRAINED_AUTHZ)));
        }
        return fineGrainedAuthzConfig;
    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }
        return Collections.emptyMap();
    }
}
