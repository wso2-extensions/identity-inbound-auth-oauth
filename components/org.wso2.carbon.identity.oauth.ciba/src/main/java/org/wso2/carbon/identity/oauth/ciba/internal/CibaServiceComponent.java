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


package org.wso2.carbon.identity.oauth.ciba.internal;

/**
 * CIBA service component class.
 */

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.ciba.service",
        immediate = true
)
public class CibaServiceComponent {

    private static final Log log = LogFactory.getLog(CibaServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            CibaServiceComponent cibaServiceComponent = new CibaServiceComponent();
            ctxt.getBundleContext().registerService(CibaServiceComponent.class, cibaServiceComponent, null);
            if (log.isDebugEnabled()) {
                log.debug("Ciba component bundle is activated");
            }
        } catch (Throwable e) {
            if(log.isDebugEnabled()){
                log.error("Ciba component bundle  activation Failed", e);
            }
        }

    }

    /**
     * Set realm service implementation
     *
     * @param realmService RealmService
     */
    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("realmService set in CibaComponent bundle");
        }
        CibaServiceDataHolder.setRealmService(realmService);
    }

    /**
     * Unset realm service implementation
     */
    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("realmService unset in CibaComponent bundle");
        }
        CibaServiceDataHolder.setRealmService(null);
    }
}