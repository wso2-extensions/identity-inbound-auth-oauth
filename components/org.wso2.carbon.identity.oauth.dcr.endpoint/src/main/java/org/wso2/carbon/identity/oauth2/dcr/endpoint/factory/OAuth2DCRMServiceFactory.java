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

package org.wso2.carbon.identity.oauth2.dcr.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;

/**
 * Factory Beans serves as a factory for creating other beans within the IOC container. This factory bean is used to
 * instantiate the DCRMService type of object inside the container.
 */
public class OAuth2DCRMServiceFactory extends AbstractFactoryBean<DCRMService> {

    private DCRMService oAuth2DCRMService;

    @Override
    public Class<DCRMService> getObjectType() {

        return DCRMService.class;
    }

    @Override
    protected DCRMService createInstance() throws Exception {

        if (this.oAuth2DCRMService == null) {
            DCRMService oAuth2DCRMService = (DCRMService) PrivilegedCarbonContext.
                    getThreadLocalCarbonContext().getOSGiService(DCRMService.class, null);
            if (oAuth2DCRMService != null) {
                this.oAuth2DCRMService = oAuth2DCRMService;
            }
        }
        return this.oAuth2DCRMService;
    }
}
