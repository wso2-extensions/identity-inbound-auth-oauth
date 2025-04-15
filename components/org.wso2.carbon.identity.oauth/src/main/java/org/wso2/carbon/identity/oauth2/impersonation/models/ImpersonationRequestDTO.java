/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.models;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;

/**
 * Request DTO class for Impersonation validation.
 */
public class ImpersonationRequestDTO {

    private String subject;
    private AuthenticatedUser impersonator;
    private String clientId;
    private String[] scopes;
    private String tenantDomain;
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;

    public String getSubject() {

        return subject;
    }

    public void setSubject(String subject) {

        this.subject = subject;
    }

    public AuthenticatedUser getImpersonator() {

        return impersonator;
    }

    public void setImpersonator(AuthenticatedUser impersonator) {

        this.impersonator = impersonator;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String[] getScopes() {

        return scopes;
    }

    public void setScopes(String[] scopes) {

        this.scopes = scopes;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }

    public OAuthAuthzReqMessageContext getoAuthAuthzReqMessageContext() {

        return oAuthAuthzReqMessageContext;
    }

    public void setoAuthAuthzReqMessageContext(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext) {

        this.oAuthAuthzReqMessageContext = oAuthAuthzReqMessageContext;
    }
}
