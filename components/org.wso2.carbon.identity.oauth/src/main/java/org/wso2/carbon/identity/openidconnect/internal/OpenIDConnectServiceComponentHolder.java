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

import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.openidconnect.ClaimProvider;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.openidconnect.handlers.RequestObjectHandler;

import java.util.ArrayList;
import java.util.List;

public class OpenIDConnectServiceComponentHolder {

    private static OpenIDConnectServiceComponentHolder instance = new OpenIDConnectServiceComponentHolder();
    private List<OpenIDConnectClaimFilter> openIDConnectClaimFilters = new ArrayList<>();
    private List<ClaimProvider> claimProviders = new ArrayList<>();
    private static RequestObjectService requestObjectService;
    private static IdentityEventService identityEventService;
    private static RequestObjectHandler requestObjectHandler;
    private ClaimMetadataManagementService claimMetadataManagementService;
    private SSOConsentService ssoConsentService;

    public static RequestObjectHandler getRequestObjectHandler() {

        return requestObjectHandler;
    }

    public static void setRequestObjectHandler(RequestObjectHandler requestObjectHandler) {

        OpenIDConnectServiceComponentHolder.requestObjectHandler = requestObjectHandler;
    }

    public static IdentityEventService getIdentityEventService() {
        return identityEventService;
    }

    public static void setIdentityEventService(IdentityEventService identityEventService) {
        OpenIDConnectServiceComponentHolder.identityEventService = identityEventService;
    }

    public static RequestObjectService getRequestObjectService() {
        return requestObjectService;
    }

    public static void setRequestObjectService(RequestObjectService requestObjectService) {
        OpenIDConnectServiceComponentHolder.requestObjectService = requestObjectService;
    }

    private OpenIDConnectServiceComponentHolder() {

    }

    public static OpenIDConnectServiceComponentHolder getInstance() {
        return instance;
    }

    /**
     * @return The OIDC Claim Filter with the highest priority.
     */
    public OpenIDConnectClaimFilter getHighestPriorityOpenIDConnectClaimFilter() {

        if (openIDConnectClaimFilters.isEmpty()) {
            throw new RuntimeException("No OpenIDConnect Claim Filters available.");
        }
        return openIDConnectClaimFilters.get(0);
    }

    public List<OpenIDConnectClaimFilter> getOpenIDConnectClaimFilters() {
        return openIDConnectClaimFilters;
    }

    /**
     * Get ClaimProvider Service
     *
     * @return all ID Token ClaimProviders who insert additional claims.
     */
    public List<ClaimProvider> getClaimProviders() {
        return claimProviders;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        this.claimMetadataManagementService = claimMetadataManagementService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {
        return claimMetadataManagementService;
    }

    public void setSsoConsentService(SSOConsentService ssoConsentService) {

        this.ssoConsentService = ssoConsentService;
    }

    public SSOConsentService getSsoConsentService() {

        return ssoConsentService;
    }
}
