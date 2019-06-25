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

package org.wso2.carbon.identity.oauth.client.authn.filter;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;

/**
 * Factory Beans serves as a factory for creating other beans within the IOC container. This factory bean is used to
 * instantiate the OAuthClientAuthnService type of object inside the container.
 */
public class OAuthClientAuthnServiceFactory extends AbstractFactoryBean<OAuthClientAuthnService> {

    public OAuthClientAuthnService oAuthClientAuthnService;


    @Override
    public Class<OAuthClientAuthnService> getObjectType() {

        return OAuthClientAuthnService.class;
    }

    @Override
    protected OAuthClientAuthnService createInstance() throws Exception {

        if (this.oAuthClientAuthnService != null) {
            return this.oAuthClientAuthnService;
        } else {
            OAuthClientAuthnService oAuthClientAuthnService = (OAuthClientAuthnService) PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiService(OAuthClientAuthnService.class, null);
            if (oAuthClientAuthnService != null) {
                this.oAuthClientAuthnService = oAuthClientAuthnService;
            }
            return oAuthClientAuthnService;
        }
    }
}
