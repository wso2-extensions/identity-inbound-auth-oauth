/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProvider;

import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Authorization Details OSGI service component.
 */
@Component(name = "org.wso2.carbon.identity.oauth.rar.internal.AuthorizationDetailsServiceComponent")
public class AuthorizationDetailsServiceComponent {
    private static final Log log = LogFactory.getLog(AuthorizationDetailsServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        AuthorizationDetailsDataHolder.getInstance().setAuthorizationDetailsProviders(
                loadAuthorizationDetailsProviders(ServiceLoader.load(AuthorizationDetailsProvider.class,
                        this.getClass().getClassLoader())));

        log.debug("AuthorizationDetailsServiceComponent is activated");
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("AuthorizationDetailsServiceComponent is deactivated");
    }

    /**
     * Loads supported authorization details providers from the provided {@link ServiceLoader}.
     *
     * @param serviceLoader {@link ServiceLoader} for {@link AuthorizationDetailsProvider}.
     * @return Set of authorization details providers.
     */
    private Set<AuthorizationDetailsProvider> loadAuthorizationDetailsProviders(
            final ServiceLoader<AuthorizationDetailsProvider> serviceLoader) {

        return StreamSupport.stream(serviceLoader.spliterator(), false)
                .collect(Collectors.toSet());
    }
}
