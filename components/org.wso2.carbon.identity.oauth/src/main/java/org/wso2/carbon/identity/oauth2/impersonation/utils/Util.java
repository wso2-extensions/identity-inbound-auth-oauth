/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.utils;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtException;
import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.ENABLE_EMAIL_NOTIFICATION;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_RESOURCE_NAME;

/**
 * Utility class providing helper methods for managing impersonation configurations.
 */
public class Util {

    /**
     * Handles server exceptions by creating an instance of ImpersonationConfigMgtServerException.
     *
     * @param error The error message and code associated with the server exception.
     * @param e     The underlying cause of the server exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of ImpersonationConfigMgtServerException.
     */
    public static ImpersonationConfigMgtException handleServerException(ErrorMessage error, Throwable e,
                                                                        String... data) {

        return new ImpersonationConfigMgtServerException(String.format(error.getDescription(), data),
                error.getCode(), e);
    }

    /**
     * Handles client exceptions by creating an instance of ImpersonationConfigMgtClientException.
     *
     * @param error The error message and code associated with the client exception.
     * @param e     The underlying cause of the client exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of ImpersonationConfigMgtClientException.
     */
    public static ImpersonationConfigMgtException handleClientException(ErrorMessage error, Throwable e,
                                                                        String... data) {

        return new ImpersonationConfigMgtClientException(String.format(error.getDescription(), data),
                error.getCode(), e);
    }

    /**
     * Parses an ImpersonationConfig object into a ResourceAdd object.
     *
     * @param impersonationConfig The impersonation configuration to be parsed.
     * @return A ResourceAdd object representing the parsed configuration.
     */
    public static ResourceAdd parseConfig(ImpersonationConfig impersonationConfig) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(IMPERSONATION_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();
        addAttribute(attributes, impersonationConfig);
        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }

    private static void addAttribute(List<Attribute> attributeList, ImpersonationConfig impersonationConfig) {

        String value = String.valueOf(impersonationConfig.isEnableEmailNotification());
        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(ENABLE_EMAIL_NOTIFICATION);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }

    /**
     * Parses a Resource object into an ImpersonationConfig object.
     *
     * @param resource The resource to be parsed.
     * @return An ImpersonationConfig object representing the parsed resource.
     */
    public static ImpersonationConfig parseResource(Resource resource) {

        ImpersonationConfig impersonationConfig = new ImpersonationConfig();
        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);
            impersonationConfig.setEnableEmailNotification(
                    Boolean.parseBoolean(attributeMap.get(ENABLE_EMAIL_NOTIFICATION)));
        }
        return impersonationConfig;
    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }
        return Collections.emptyMap();
    }

    /**
     * Retrieves the default impersonation configuration.
     *
     * @return The default ImpersonationConfig object.
     */
    public static ImpersonationConfig getDefaultConfiguration() {

        ImpersonationConfig impersonationConfig = new ImpersonationConfig();
        impersonationConfig.setEnableEmailNotification(true);
        return impersonationConfig;
    }
}

