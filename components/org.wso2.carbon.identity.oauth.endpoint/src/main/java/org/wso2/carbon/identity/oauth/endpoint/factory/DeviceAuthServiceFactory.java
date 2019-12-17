/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;

/**
 * This class is used to register DeviceAuthService as a factory bean.
 */
public class DeviceAuthServiceFactory extends AbstractFactoryBean<DeviceAuthService> {

    private DeviceAuthService deviceAuthService;

    @Override
    public Class<DeviceAuthService> getObjectType() {

        return DeviceAuthService.class;
    }

    @Override
    protected DeviceAuthService createInstance() throws Exception {

        if (this.deviceAuthService != null) {
            return this.deviceAuthService;
        } else {
            DeviceAuthService deviceAuthService = (DeviceAuthService)
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().
                            getOSGiService(DeviceAuthService.class, null);
            if (deviceAuthService != null) {
                this.deviceAuthService = deviceAuthService;
            }
            return deviceAuthService;
        }
    }
}
