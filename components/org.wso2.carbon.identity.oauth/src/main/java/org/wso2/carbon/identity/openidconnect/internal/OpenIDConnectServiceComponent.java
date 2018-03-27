/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectSystemClaimImpl;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.openidconnect.handlers.RequestObjectHandler;

import java.util.Comparator;

@Component(
        name = "identity.openidconnect.component",
        immediate = true
)
public class OpenIDConnectServiceComponent {

    private Log log = LogFactory.getLog(OpenIDConnectServiceComponent.class);
    private BundleContext bundleContext;

    protected void activate(ComponentContext context) {

        try {
            bundleContext = context.getBundleContext();
            bundleContext.registerService(ClaimProvider.class.getName(), new OpenIDConnectSystemClaimImpl(), null);
            bundleContext.registerService(AbstractEventHandler.class.getName(),
                    new RequestObjectHandler(), null);
            bundleContext.registerService(RequestObjectService.class.getName(),
                    new RequestObjectService(), null);
        } catch (Throwable e) {
            log.error("Error while activating OpenIDConnectServiceComponent.", e);
        }
    }

    /**
     * Set {@link OpenIDConnectClaimFilter} implementation
     *
     * @param openIDConnectClaimFilter an implementation of {@link OpenIDConnectClaimFilter}
     */
    @Reference(
            name = "openid.connect.claim.filter.service",
            service = OpenIDConnectClaimFilter.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOpenIDConnectClaimFilter"
    )
    protected void setOpenIDConnectClaimFilter(OpenIDConnectClaimFilter openIDConnectClaimFilter) {

        if (log.isDebugEnabled()) {
            log.debug("OpenIDConnectClaimFilter: " + openIDConnectClaimFilter.getClass().getName() + " set in " +
                    "OpenIDConnectServiceComponent.");
        }
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters().add(openIDConnectClaimFilter);
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters()
                .sort(getOIDCClaimFilterComparator());
    }

    private Comparator<OpenIDConnectClaimFilter> getOIDCClaimFilterComparator() {
        // Sort based on priority in descending order, ie. highest priority comes to the first element of the list.
        return Comparator.comparingInt(OpenIDConnectClaimFilter::getPriority).reversed();
    }

    /**
     * Unset {@link OpenIDConnectClaimFilter} implementation
     *
     * @param openIDConnectClaimFilter registerd implementation of {@link OpenIDConnectClaimFilter}
     */
    protected void unsetOpenIDConnectClaimFilter(OpenIDConnectClaimFilter openIDConnectClaimFilter) {

        if (log.isDebugEnabled()) {
            log.debug("OpenIDConnectClaimFilter: " + openIDConnectClaimFilter.getClass().getName() + " unset in " +
                    "OpenIDConnectServiceComponent.");
        }
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters()
                .remove(openIDConnectClaimFilter);
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters()
                .sort(getOIDCClaimFilterComparator());
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "ClaimProvider",
            service = ClaimProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimProvider"
    )
    protected void setClaimProvider(ClaimProvider claimProvider) {

        if (log.isDebugEnabled()) {
            log.debug("Setting ClaimProvider Service " + claimProvider.getClass().getName());
        }
        OpenIDConnectServiceComponentHolder.getInstance().getClaimProviders().add(claimProvider);
    }

    protected void unsetClaimProvider(ClaimProvider claimProvider) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting ClaimProvider Service " + claimProvider.getClass().getName());
        }
        OpenIDConnectServiceComponentHolder.getInstance().getClaimProviders().remove(claimProvider);
    }

    @Reference(
            name = "org.wso2.carbon.identity.event.services. ",
            service = IdentityEventService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService"
    )
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService set in OpenIDConnectServiceComponent bundle");
        }
        OpenIDConnectServiceComponentHolder.setIdentityEventService(identityEventService);
    }

    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService unset in OpenIDConnectServiceComponent bundle");
        }
        OpenIDConnectServiceComponentHolder.setIdentityEventService(null);
    }

    @Reference(
            name = "identity.openidconnect.RequestObjectService",
            service = RequestObjectService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRequestObjectService"
    )
    protected void setRequestObjectService(RequestObjectService requestObjectService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting RequestObjectService in OpenIDConnectServiceComponent bundle.");
        }
        OpenIDConnectServiceComponentHolder.setRequestObjectService(requestObjectService);
    }

    protected void unsetRequestObjectService(RequestObjectService requestObjectService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting RequestObjectService in OpenIDConnectServiceComponent bundle.");
        }
        OpenIDConnectServiceComponentHolder.setRequestObjectService(null);
    }

    @Reference(
            name = "identity.openidconnect.handlers",
            service = RequestObjectHandler.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRequestObjectRevokeHandler"
    )
    protected void setRequestObjectRevokeHandler(RequestObjectHandler requestObjectHandler) {

        if (log.isDebugEnabled()) {
            log.debug("RequestObjectHandler set in OpenIDConnectServiceComponent bundle");
        }
        OpenIDConnectServiceComponentHolder.setRequestObjectHandler(requestObjectHandler);
    }

    protected void unsetRequestObjectRevokeHandler(RequestObjectHandler requestObjectHandler) {

        if (log.isDebugEnabled()) {
            log.debug("RequestObjectHandler unset in OpenIDConnectServiceComponent bundle");
        }
        OpenIDConnectServiceComponentHolder.setRequestObjectHandler(null);
    }

    @Reference(
            name = "claim.manager.listener.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimManagementService"
    )
    protected void setClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        OpenIDConnectServiceComponentHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
    }

    protected void unsetClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        OpenIDConnectServiceComponentHolder.getInstance()
                .setClaimMetadataManagementService(null);
    }

    @Reference(
            name = "sso.consent.service",
            service = SSOConsentService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConsentManagementService"
    )
    protected void setConsentManagementService(SSOConsentService ssoConsentService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the SSOConsentService.");
        }
        OpenIDConnectServiceComponentHolder.getInstance().setSsoConsentService(ssoConsentService);
    }

    protected void unsetConsentManagementService(SSOConsentService ssoConsentService) {

        if (log.isDebugEnabled()) {
            log.debug("Un setting the SSOConsentService");
        }
        OpenIDConnectServiceComponentHolder.getInstance().setSsoConsentService(null);
    }

}
