/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.fapi.utils;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtException;
import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiConfig;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiProfileEnum;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_ENABLED;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth2.fapi.utils.Constants.FAPI_SUPPORTED_PROFILES;

/**
 * Utility class providing helper methods for managing FAPI configurations.
 */
public class FapiUtil {

    public static final String COMMA_SEPARATOR = ",";
    private static final Log log = LogFactory.getLog(FapiUtil.class);

    private FapiUtil() {

    }

    private static Optional<OAuthAppDO> getFapiConformantApp(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        String accessingOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getAccessingOrganizationId();
        if (StringUtils.isNotBlank(accessingOrgId)) {
            return Optional.of(OAuth2Util.getAppInformationFromOrgHierarchy(clientId, accessingOrgId));
        } else {
            return Optional.of(OAuth2Util.getAppInformationByClientId(clientId, tenantDomain));
        }
    }

    /**
     * Check whether the application should be FAPI conformant.
     *
     * @param clientId Client ID of the application.
     * @return Whether the application should be FAPI conformant.
     * @throws IdentityOAuth2Exception InvalidOAuthClientException
     */
    public static boolean isFapiConformantApp(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI))) {
            return false;
        }
        return FapiUtil.getFapiConformantApp(clientId)
                .map(OAuthAppDO::isFapiConformanceEnabled)
                .orElse(false);
    }

    public static boolean isFapiConformantApp(String clientId, FapiProfileEnum fapiProfile)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(OAuthConstants.ENABLE_FAPI))) {
            return false;
        }
        return FapiUtil.getFapiConformantApp(clientId)
                .map(oAuthAppDo -> fapiProfile.value().equals(oAuthAppDo.getFapiProfile()))
                .orElse(false);
    }

    public static boolean isFapi1AdvancedProfileCompliant(String clientId) {

        try {
            return FapiUtil.isFapiConformantApp(clientId, FapiProfileEnum.FAPI1_ADVANCED);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while checking FAPI conformance for clientId: " + clientId, e);
            }
        }
        return false;
    }

    public static boolean isFapi2SecurityProfileCompliant(String clientId) {

        try {
            return FapiUtil.isFapiConformantApp(clientId, FapiProfileEnum.FAPI2_SECURITY);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while checking FAPI conformance for clientId: " + clientId, e);
            }
        }
        return false;
    }

    /**
     * Handles exceptions by wrapping them in a FapiConfigMgtException.
     *
     * @param error The error message and code associated with the exception.
     * @param e     The underlying cause of the exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of FapiConfigMgtException.
     */
    public static FapiConfigMgtException handleException(ErrorMessage error, Throwable e, String... data) {

        return new FapiConfigMgtException(String.format(error.getDescription(), (Object[]) data), error.getCode(), e);
    }

    /**
     * Wraps a client-side error in a {@link FapiConfigMgtClientException}.
     *
     * @param error The error message and code.
     * @param e     The underlying cause.
     * @param data  Additional context data for the error description.
     * @return A {@link FapiConfigMgtClientException} (HTTP 4xx).
     */
    public static FapiConfigMgtClientException handleClientException(ErrorMessage error, Throwable e,
                                                                     String... data) {

        return new FapiConfigMgtClientException(
                String.format(error.getDescription(), (Object[]) data), error.getCode(), e);
    }

    /**
     * Wraps a server-side error in a {@link FapiConfigMgtServerException}.
     *
     * @param error The error message and code.
     * @param e     The underlying cause.
     * @param data  Additional context data for the error description.
     * @return A {@link FapiConfigMgtServerException} (HTTP 5xx).
     */
    public static FapiConfigMgtServerException handleServerException(ErrorMessage error, Throwable e,
                                                                     String... data) {

        return new FapiConfigMgtServerException(
                String.format(error.getDescription(), (Object[]) data), error.getCode(), e);
    }

    /**
     * Parses a FapiConfig object into a ResourceAdd object for persistence.
     *
     * @param fapiConfig The FAPI configuration to be parsed.
     * @return A ResourceAdd object representing the parsed configuration.
     */
    public static ResourceAdd parseConfig(FapiConfig fapiConfig) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(FAPI_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();
        addAttribute(attributes, FAPI_ENABLED, String.valueOf(fapiConfig.isEnabled()));
        addAttribute(attributes, FAPI_SUPPORTED_PROFILES, toCommaSeparated(fapiConfig.getSupportedProfiles()));
        resourceAdd.setAttributes(attributes);
        return resourceAdd;
    }

    /**
     * Parses a Resource object into a FapiConfig object.
     *
     * @param resource The resource to be parsed.
     * @return A FapiConfig object representing the parsed resource.
     */
    public static FapiConfig parseResource(Resource resource) {

        FapiConfig fapiConfig = new FapiConfig();
        if (resource.isHasAttribute()) {
            Map<String, String> attributeMap = getAttributeMap(resource.getAttributes());
            fapiConfig.setEnabled(Boolean.parseBoolean(attributeMap.get(FAPI_ENABLED)));
            fapiConfig.setSupportedProfiles(fromCommaSeparated(attributeMap.get(FAPI_SUPPORTED_PROFILES))
                    .stream().map(FapiProfileEnum::fromValue).collect(Collectors.toList()));
        }
        return fapiConfig;
    }

    /**
     * Retrieves the default FAPI configuration.
     *
     * @return The default FapiConfig object with enforcement disabled and empty profile lists.
     */
    public static FapiConfig getDefaultConfiguration() {

        FapiConfig fapiConfig = new FapiConfig();
        fapiConfig.setEnabled(true);
        fapiConfig.setSupportedProfiles(Collections.singletonList(FapiProfileEnum.FAPI1_ADVANCED));
        return fapiConfig;
    }

    private static void addAttribute(List<Attribute> attributeList, String key, String value) {

        Attribute attribute = new Attribute();
        attribute.setKey(key);
        attribute.setValue(value != null ? value : StringUtils.EMPTY);
        attributeList.add(attribute);
    }

    private static String toCommaSeparated(List<FapiProfileEnum> fapiProfiles) {

        if (CollectionUtils.isEmpty(fapiProfiles)) {
            return StringUtils.EMPTY;
        }
        return fapiProfiles.stream().map(FapiProfileEnum::value).collect(Collectors.joining(COMMA_SEPARATOR));
    }

    private static List<String> fromCommaSeparated(String value) {

        if (StringUtils.isBlank(value)) {
            return Collections.emptyList();
        }
        return new ArrayList<>(Arrays.asList(value.split(COMMA_SEPARATOR)));
    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }
        return Collections.emptyMap();
    }
}
