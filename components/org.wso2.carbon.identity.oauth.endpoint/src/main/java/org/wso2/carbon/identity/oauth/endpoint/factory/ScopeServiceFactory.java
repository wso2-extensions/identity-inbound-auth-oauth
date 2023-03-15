/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;

import java.util.List;

/**
 * Factory bean for ScopeService.
 */
public class ScopeServiceFactory extends AbstractFactoryBean<ScopeMetadataService> {

    private ScopeMetadataService scopeMetadataService;

    private static final Log log = LogFactory.getLog(ScopeServiceFactory.class);

    @Override
    public Class<ScopeMetadataService> getObjectType() {

        return ScopeMetadataService.class;
    }

    @Override
    protected ScopeMetadataService createInstance() throws Exception {

        if (this.scopeMetadataService == null) {

            // Get the OSGi service registered for ScopeService interface.
            List<Object> scopeServices = PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiServices(ScopeMetadataService.class, null);

            if (scopeServices == null || scopeServices.isEmpty()) {
                throw new IdentityOAuth2ServerException("No ScopeService implementation found.");
            }

            if (scopeServices.size() > 1) {
                log.debug("More than one ScopeService implementations found. Returning the first one which is not" +
                        " OAuth2ScopeService.");
                for (Object scopeService : scopeServices) {
                    if (scopeService instanceof OAuth2ScopeService) {
                        continue;
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Returning the ScopeService: " + scopeService.getClass().getName());
                    }
                    this.scopeMetadataService = (ScopeMetadataService) scopeService;
                }
            } else {
                this.scopeMetadataService = (ScopeMetadataService) scopeServices.get(0);
            }
        }
        return this.scopeMetadataService;
    }

}
