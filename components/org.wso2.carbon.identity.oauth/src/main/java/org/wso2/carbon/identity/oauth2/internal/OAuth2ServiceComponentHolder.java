/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.registry.core.service.RegistryService;

/**
 * OAuth2 Service component data holder
 */
public class OAuth2ServiceComponentHolder {

    private static ApplicationManagementService applicationMgtService;
    private static boolean pkceEnabled = false;
    private static boolean tbEnabled = false;
    private static RegistryService registryService;
    private OAuth2ServiceComponentHolder(){

    }

    public static boolean isTbEnabled() {
        return tbEnabled;
    }

    public static void setTbEnabled(boolean tbEnabled) {
        OAuth2ServiceComponentHolder.tbEnabled = tbEnabled;
    }

    /**
     * Get Application management service
     *
     * @return ApplicationManagementService
     */
    public static ApplicationManagementService getApplicationMgtService() {
        return OAuth2ServiceComponentHolder.applicationMgtService;
    }

    /**
     * Set Application management service
     *
     * @param applicationMgtService ApplicationManagementService
     */
    public static void setApplicationMgtService(ApplicationManagementService applicationMgtService) {
        OAuth2ServiceComponentHolder.applicationMgtService = applicationMgtService;
    }

    public static boolean isPkceEnabled() {
        return pkceEnabled;
    }

    public static void setPkceEnabled(boolean pkceEnabled) {
        OAuth2ServiceComponentHolder.pkceEnabled = pkceEnabled;
    }

    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {
        OAuth2ServiceComponentHolder.registryService = registryService;
    }
}
