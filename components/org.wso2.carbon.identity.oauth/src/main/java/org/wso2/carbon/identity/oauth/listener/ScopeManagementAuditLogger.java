/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * Log audit events in scope management.
 */
public class ScopeManagementAuditLogger extends AbstractEventHandler {

    private static final Log audit = CarbonConstants.AUDIT_LOG;
    private static final String AUDIT_MESSAGE = "Initiator : %s | Action : %s | Target : %s | Data : { %s } | Result" +
            " : %s ";
    private static final String SUCCESS = "Success";

    private static final Log log = LogFactory.getLog(ScopeManagementAuditLogger.class);

    /**
     * This handles the OAuth scope related operations that are subscribed and publish audit logs for those operations.
     *
     * @param event Event.
     * @throws IdentityEventException IdentityEventException.
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        int tenantId = (int) event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_ID);
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        if (log.isDebugEnabled()) {
            log.debug(event.getEventName() + " event received to ScopeManagementAuditLogger for the " +
                    "tenant: " + tenantDomain);
        }

        if (IdentityEventConstants.Event.POST_ADD_SCOPE.equals(event.getEventName())) {
            String scopeName =
                    (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_NAME);
            String initiator = getInitiatorUsername(tenantDomain);
            String data = buildScopeData(event);
            audit.info(String.format(AUDIT_MESSAGE, initiator, "Add-Scope", scopeName, data,
                    SUCCESS));
        } else if (IdentityEventConstants.Event.POST_UPDATE_SCOPE.equals(event.getEventName())) {
            String scopeName =
                    (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_NAME);
            String initiator = getInitiatorUsername(tenantDomain);
            String data = buildScopeData(event);
            audit.info(String.format(AUDIT_MESSAGE, initiator, "Update-Scope", scopeName, data,
                    SUCCESS));
        } else if (IdentityEventConstants.Event.POST_DELETE_SCOPE.equals(event.getEventName())) {
            String scopeName =
                    (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_NAME);
            String initiator = getInitiatorUsername(tenantDomain);
            audit.info(String.format(AUDIT_MESSAGE, initiator, "Delete-Scope", scopeName, null,
                    SUCCESS));
        }
    }

    @Override
    public String getName() {

        return "ScopeManagementAuditLogger";
    }

    private String getInitiatorUsername(String tenantDomain) {

        String user = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (StringUtils.isNotBlank(user)) {
            // Append tenant domain to username build the full qualified username of initiator.
            user = UserCoreUtil.addTenantDomainToEntry(user, tenantDomain);
        } else {
            user = CarbonConstants.REGISTRY_SYSTEM_USERNAME;
        }
        return user;
    }

    private String buildScopeData(Event event) {

        String name =
                (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_NAME);
        String description =
                (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_DESCRIPTION);
        String displayName =
                (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_DISPLAY_NAME);
        String[] claims =
                (String[]) event.getEventProperties().get(IdentityEventConstants.EventProperty.SCOPE_CLAIMS);

        StringBuilder data = new StringBuilder();
        data.append("Name:").append(name).append(", Description:").append(description).append(", Display Name:")
                .append(displayName).append(", Claims:[");
        if (ArrayUtils.isNotEmpty(claims)) {
            String joiner = "";
            for (String claim : claims) {
                data.append(joiner);
                joiner = ", ";
                data.append(claim);
            }
        }
        data.append("]");
        return data.toString();
    }
}
