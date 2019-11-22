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
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;

/**
 * Factory Beans serves as a factory for creating other beans within the IOC container. This factory bean is used to
 * instantiate the OAuthServerConfiguration type of object inside the container.
 */
public class OAuthServerConfigurationFactory extends AbstractFactoryBean<OAuthServerConfiguration> {

    private OAuthServerConfiguration oAuthServerConfiguration;

    @Override
    public Class<OAuthServerConfiguration> getObjectType() {

        return OAuthServerConfiguration.class;
    }

    @Override
    protected OAuthServerConfiguration createInstance() throws Exception {

        if (this.oAuthServerConfiguration != null) {
            return this.oAuthServerConfiguration;
        } else {
            OAuthServerConfiguration oAuthServerConfiguration = (OAuthServerConfiguration) PrivilegedCarbonContext.
                    getThreadLocalCarbonContext().getOSGiService(OAuthServerConfiguration.class, null);
            if (oAuthServerConfiguration != null) {
                this.oAuthServerConfiguration = oAuthServerConfiguration;
            }
            return oAuthServerConfiguration;
        }
    }
}
