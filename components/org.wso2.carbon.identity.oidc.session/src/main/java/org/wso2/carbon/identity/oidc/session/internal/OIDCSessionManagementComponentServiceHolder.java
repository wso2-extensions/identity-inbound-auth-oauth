/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session.internal;

import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oidc.session.handler.OIDCLogoutHandler;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class OIDCSessionManagementComponentServiceHolder {
    private static HttpService httpService;
    private static RealmService realmService;
    private static List<OIDCLogoutHandler> OIDCPostLogoutHandlers = new ArrayList<>();
    private static ApplicationManagementService applicationMgtService;

    private OIDCSessionManagementComponentServiceHolder() {

    }

    public static HttpService getHttpService() {
        return httpService;
    }

    public static void setHttpService(HttpService httpService) {
        OIDCSessionManagementComponentServiceHolder.httpService = httpService;
    }
    public static void setRealmService(RealmService realmService) {
        OIDCSessionManagementComponentServiceHolder.realmService = realmService;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    public static List<OIDCLogoutHandler> getOIDCLogoutHandlers() {
        return Collections.unmodifiableList(OIDCPostLogoutHandlers);
    }

    public static void addPostLogoutHandler(OIDCLogoutHandler OIDCPostLogoutHandler) {
        OIDCPostLogoutHandlers.add(OIDCPostLogoutHandler);;
    }

    public static void removePostLogoutHandler(OIDCLogoutHandler OIDCPostLogoutHandler) {
        OIDCPostLogoutHandlers.remove(OIDCPostLogoutHandler);
    }

    /**
     * Get Application management service
     *
     * @return ApplicationManagementService
     */
    public static ApplicationManagementService getApplicationMgtService() {
        return OIDCSessionManagementComponentServiceHolder.applicationMgtService;
    }

    /**
     * Set Application management service
     *
     * @param applicationMgtService ApplicationManagementService
     */
    public static void setApplicationMgtService(ApplicationManagementService applicationMgtService) {
        OIDCSessionManagementComponentServiceHolder.applicationMgtService = applicationMgtService;
    }
}
