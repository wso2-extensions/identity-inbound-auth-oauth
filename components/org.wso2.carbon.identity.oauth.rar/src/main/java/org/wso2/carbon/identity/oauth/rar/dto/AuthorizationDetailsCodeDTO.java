/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.rar.dto;

import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;

/**
 * Data Transfer Object (DTO) for representing authorization details along with authorization code.
 * This class extends {@link AuthorizationDetailsDTO} to include additional fields for authorization code ID.
 */
public class AuthorizationDetailsCodeDTO extends AuthorizationDetailsDTO {

    final String codeId;

    /**
     * Constructs an {@link AuthorizationDetailsCodeDTO} with all required fields.
     *
     * @param codeId              the authorization code ID associated with the authorization detail.
     * @param typeId              the type ID of the authorization detail.
     * @param authorizationDetail the {@link AuthorizationDetail} object.
     * @param tenantId            the tenant ID.
     */
    public AuthorizationDetailsCodeDTO(final String codeId, final String typeId,
                                       final String authorizationDetail, final int tenantId) {

        super(null, typeId, authorizationDetail, tenantId);
        this.codeId = codeId;
    }

    /**
     * Constructs an {@link AuthorizationDetailsCodeDTO} with essential fields.
     *
     * @param codeId              the authorization code ID associated with the authorization detail.
     * @param authorizationDetail the {@link AuthorizationDetail} object.
     * @param tenantId            the tenant ID.
     */
    public AuthorizationDetailsCodeDTO(final String codeId, final AuthorizationDetail authorizationDetail,
                                       final int tenantId) {

        super(authorizationDetail, tenantId);
        this.codeId = codeId;
    }

    /**
     * Gets the authorization code ID associated with the authorization detail.
     *
     * @return the authorization code ID.
     */
    public String getAuthorizationCodeId() {
        return this.codeId;
    }
}
