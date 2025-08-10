/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Data Transfer Object (DTO) for handling impersonation notification requests.
 */
public class ImpersonationNotificationRequestDTO {

    private AuthenticatedUser subject;
    private String impersonator;
    private String tenantDomain;
    private OAuthTokenReqMessageContext tokenReqMessageContext;

    public AuthenticatedUser getSubject() {

        return subject;
    }

    public void setSubject(AuthenticatedUser subject) {

        this.subject = subject;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }

    public String getImpersonator() {

        return impersonator;
    }

    public void setImpersonator(String impersonator) {

        this.impersonator = impersonator;
    }

    public OAuthTokenReqMessageContext getTokenReqMessageContext() {

        return tokenReqMessageContext;
    }

    public void setTokenReqMessageContext(OAuthTokenReqMessageContext tokenReqMessageContext) {

        this.tokenReqMessageContext = tokenReqMessageContext;
    }
}
