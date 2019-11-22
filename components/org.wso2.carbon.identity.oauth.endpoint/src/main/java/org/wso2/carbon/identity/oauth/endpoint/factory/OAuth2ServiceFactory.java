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
import org.wso2.carbon.identity.oauth2.OAuth2Service;

/**
 * Factory Beans serves as a factory for creating other beans within the IOC container. This factory bean is used to
 * instantiate the OAuth2Service type of object inside the container.
 */
public class OAuth2ServiceFactory extends AbstractFactoryBean<OAuth2Service> {

    private OAuth2Service oauth2Service;

    @Override
    public Class<OAuth2Service> getObjectType() {

        return OAuth2Service.class;
    }

    @Override
    protected OAuth2Service createInstance() throws Exception {

        if (this.oauth2Service != null) {
            return this.oauth2Service;
        } else {
            OAuth2Service OAuth2Service = (OAuth2Service) PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
            if (OAuth2Service != null) {
                this.oauth2Service = OAuth2Service;
            }
            return OAuth2Service;
        }
    }
}
