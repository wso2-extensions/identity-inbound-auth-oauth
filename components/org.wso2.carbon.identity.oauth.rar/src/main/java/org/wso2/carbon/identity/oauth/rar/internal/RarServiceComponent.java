/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
package org.wso2.carbon.identity.oauth.rar.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidator;
import org.wso2.carbon.identity.oauth.rar.core.AuthorizationDetailsSchemaValidatorImpl;

/**
 * Service component for RAR.
 */
@Component(name = "org.wso2.carbon.identity.oauth.rar.internal.RarServiceComponent", immediate = true)
public class RarServiceComponent {

    private static final Log log = LogFactory.getLog(RarServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            log.debug("RAR component bundle is activating.");

            context.getBundleContext().registerService(AuthorizationDetailsSchemaValidator.class,
                    AuthorizationDetailsSchemaValidatorImpl.getInstance(), null);

            log.debug("RAR component bundle is activated.");
        } catch (Throwable e) {
            log.error("Error occurred while activating RAR component.", e);
        }
    }

    protected void deactivate(ComponentContext context) {

        log.debug("RAR component bundle is deactivated.");
    }
}

