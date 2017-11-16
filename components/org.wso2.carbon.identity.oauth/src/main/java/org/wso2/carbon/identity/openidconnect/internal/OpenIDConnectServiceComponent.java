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

import edu.emory.mathcs.backport.java.util.Collections;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;

import java.util.Comparator;

@Component(
        name = "identity.openidconnect.component",
        immediate = true
)
public class OpenIDConnectServiceComponent {

    private Log log = LogFactory.getLog(OpenIDConnectServiceComponent.class);

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
        Collections.sort(OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters(),
                getOIDCClaimFilterComparator());
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
        OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters().remove(openIDConnectClaimFilter);
        Collections.sort(OpenIDConnectServiceComponentHolder.getInstance().getOpenIDConnectClaimFilters(),
                getOIDCClaimFilterComparator());
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
}
