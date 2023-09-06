/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.par.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.oauth.par.core.ParAuthService;
import org.wso2.carbon.identity.oauth.par.core.ParAuthServiceImpl;
import org.wso2.carbon.identity.oauth.par.core.ParRequestBuilder;
import org.wso2.carbon.identity.oauth2.OAuthAuthorizationRequestBuilder;

/**
 * Service component for PAR.
 */
@Component(
        name = "identity.oauth.par.service.component",
        immediate = true
)
public class ParServiceComponent {

    private static final Log log = LogFactory.getLog(ParServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            ParAuthService parAuthServiceImpl = new ParAuthServiceImpl();
            ParAuthServiceComponentDataHolder.getInstance().setParAuthService(parAuthServiceImpl);

            context.getBundleContext().registerService(ParAuthService.class.getName(),
                    parAuthServiceImpl, null);
            context.getBundleContext().registerService(OAuthAuthorizationRequestBuilder.class.getName(),
                    new ParRequestBuilder(), null);
            log.debug("PAR component bundle is activated.");
        } catch (Throwable e) {
            log.error("Error occurred while activating PAR component.", e);
        }
    }

    protected void deactivate(ComponentContext context) {

        log.debug("PAR component bundle is deactivated.");
    }
}
