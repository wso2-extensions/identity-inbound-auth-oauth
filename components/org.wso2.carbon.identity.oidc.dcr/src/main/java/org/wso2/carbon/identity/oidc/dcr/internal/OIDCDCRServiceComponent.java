/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.dcr.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oidc.dcr.factory.HttpOIDCRegistrationResponseFactory;
import org.wso2.carbon.identity.oidc.dcr.factory.OIDCRegistrationRequestFactory;
import org.wso2.carbon.identity.oidc.dcr.processor.OIDCDCRProcessor;

@Component(
        name = "identity.oidc.dcr",
        immediate = true
)
public class OIDCDCRServiceComponent {

    private static final Log log = LogFactory.getLog(OIDCDCRServiceComponent.class);

    @SuppressWarnings("unused")
    protected void activate(ComponentContext componentContext) {

        try {

            componentContext.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(),
                    new OIDCRegistrationRequestFactory(), null);
            componentContext.getBundleContext().registerService(IdentityProcessor.class.getName(),
                    new OIDCDCRProcessor(), null);
            componentContext.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                    new HttpOIDCRegistrationResponseFactory(), null);
        } catch (Throwable e) {
            log.error("Error occurred while activating OIDCDCRServiceComponent", e);
        }
    }

    @SuppressWarnings("unused")
    protected void deactivate(ComponentContext componentContext) {

        if (log.isDebugEnabled()) {
            log.debug("Stopping OIDCDCRServiceComponent");
        }
    }


    /**
     * Sets ApplicationManagement Service.
     *
     * @param applicationManagementService An instance of ApplicationManagementService
     */
    @Reference(
            name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting ApplicationManagement Service.");
        }
        OIDCDCRDataHolder.getInstance().
                setApplicationManagementService(applicationManagementService);
    }

    /**
     * Unsets ApplicationManagement Service.
     *
     * @param applicationManagementService An instance of ApplicationManagementService
     */
    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting ApplicationManagement Service.");
        }
        OIDCDCRDataHolder.getInstance().setApplicationManagementService(null);
    }


}
