/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.dcr.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.dcr.handler.RegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.handler.UnRegistrationHandler;

import java.util.ArrayList;
import java.util.List;

/**
 * This is the DataHolder class of DynamicClientRegistration bundle. This holds a reference to the
 * ApplicationManagementService.
 */
public class DCRDataHolder {

    private static DCRDataHolder thisInstance = new DCRDataHolder();
    private ApplicationManagementService applicationManagementService = null;
    private List<RegistrationHandler> registrationHandlerList = new ArrayList<>();
    private List<UnRegistrationHandler> unRegistrationHandlerList = new ArrayList<>();

    private DCRDataHolder() {
    }

    public static DCRDataHolder getInstance() {
        return thisInstance;
    }

    public ApplicationManagementService getApplicationManagementService() {
        if (applicationManagementService == null) {
            throw new IllegalStateException("ApplicationManagementService is not initialized properly");
        }
        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        this.applicationManagementService = applicationManagementService;
    }

    public List<RegistrationHandler> getRegistrationHandlerList() {
        return registrationHandlerList;
    }

    public void setRegistrationHandlerList(
            List<RegistrationHandler> registrationHandlerList) {
        this.registrationHandlerList = registrationHandlerList;
    }


    public List<UnRegistrationHandler> getUnRegistrationHandlerList() {
        return unRegistrationHandlerList;
    }

    public void setUnRegistrationHandlerList(
            List<UnRegistrationHandler> unRegistrationHandlerList) {
        this.unRegistrationHandlerList = unRegistrationHandlerList;
    }
}
