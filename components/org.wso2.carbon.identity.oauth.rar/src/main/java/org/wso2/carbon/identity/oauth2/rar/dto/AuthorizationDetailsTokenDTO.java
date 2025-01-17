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

package org.wso2.carbon.identity.oauth2.rar.dto;

import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;

/**
 * Data Transfer Object (DTO) for representing authorization details along with access token information.
 * This class extends {@link AuthorizationDetailsDTO} to include additional fields for access token ID.
 */
public class AuthorizationDetailsTokenDTO extends AuthorizationDetailsDTO {

    final String accessTokenId;

    /**
     * Constructs an {@link AuthorizationDetailsTokenDTO} with all required fields.
     *
     * @param id                  the ID of the authorization detail DTO.
     * @param accessTokenId       the access token ID associated with the authorization detail.
     * @param typeId              the type ID of the authorization detail.
     * @param authorizationDetail the {@link AuthorizationDetail} object.
     * @param tenantId            the tenant ID.
     */
    public AuthorizationDetailsTokenDTO(final String id, final String accessTokenId, final String typeId,
                                        final String authorizationDetail, final int tenantId) {

        super(id, typeId, authorizationDetail, tenantId);
        this.accessTokenId = accessTokenId;
    }

    /**
     * Constructs an {@link AuthorizationDetailsTokenDTO} with essential fields.
     *
     * @param accessTokenId       the access token ID associated with the authorization detail.
     * @param authorizationDetail the {@link AuthorizationDetail} object.
     * @param tenantId            the tenant ID.
     */
    public AuthorizationDetailsTokenDTO(final String accessTokenId, final AuthorizationDetail authorizationDetail,
                                        final int tenantId) {

        super(authorizationDetail, tenantId);
        this.accessTokenId = accessTokenId;
    }

    /**
     * Gets the access token ID associated with the authorization detail.
     *
     * @return the access token ID.
     */
    public String getAccessTokenId() {
        return this.accessTokenId;
    }
}
