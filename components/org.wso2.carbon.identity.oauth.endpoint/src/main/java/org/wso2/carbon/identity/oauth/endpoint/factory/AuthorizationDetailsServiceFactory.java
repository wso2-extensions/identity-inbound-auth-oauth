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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.factory;

import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;

/**
 * This class is used to register AuthorizationDetailsService as a factory bean.
 */
public class AuthorizationDetailsServiceFactory extends AbstractFactoryBean<AuthorizationDetailsService> {

    private AuthorizationDetailsService authorizationDetailsService;

    @Override
    public Class<AuthorizationDetailsService> getObjectType() {

        return AuthorizationDetailsService.class;
    }

    @Override
    protected AuthorizationDetailsService createInstance() throws Exception {

        if (this.authorizationDetailsService == null) {
            this.authorizationDetailsService =
                    OAuth2ServiceComponentHolder.getInstance().getAuthorizationDetailsService();
        }
        return this.authorizationDetailsService;
    }
}
