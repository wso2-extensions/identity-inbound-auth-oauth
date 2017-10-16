/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.discovery.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;

/**
 * Service component for OpenID Connect Discovery.
 */
@Component(
        name = "identity.discovery.component",
        immediate = true
)
public class OIDCDiscoveryServiceComponent {
    private static Log log = LogFactory.getLog(OIDCDiscoveryServiceComponent.class);
    private static BundleContext bundleContext = null;

    public static BundleContext getBundleContext() {
        return bundleContext;
    }

    protected void activate(ComponentContext context) {
        try {
            bundleContext = context.getBundleContext();
            bundleContext.registerService(OIDCProcessor.class.getName(), DefaultOIDCProcessor.getInstance(), null);
            // exposing server configuration as a service
            if (log.isDebugEnabled()) {
                log.debug("Identity OIDCDiscovery bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating OIDCDiscoveryServiceComponent", e);
        }
    }

    @Reference(
            name = "claim.manager.listener.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimManagementService"
    )
    protected void setClaimManagementService(ClaimMetadataManagementService registryService) {
        OIDCDiscoveryDataHolder.getInstance().setClaimManagementService(registryService);
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity Claim Management bundle");
        }
    }

    protected void unsetClaimManagementService(ClaimMetadataManagementService registryService) {
        OIDCDiscoveryDataHolder.getInstance().setClaimManagementService(null);
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in Identity Claim Management bundle");
        }
    }

}
