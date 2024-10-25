/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsCommonUtils.fromJSON;

/**
 * Data Transfer Object (DTO) for representing authorization details.
 * <p> This class encapsulates the details of authorization, including the ID, type ID,
 * authorization detail object, and tenant ID.
 */
public class AuthorizationDetailsDTO {

    final String id;
    final String typeId;
    final AuthorizationDetail authorizationDetail;
    final int tenantId;

    /**
     * Constructs an AuthorizationDetailsDTO with all fields.
     *
     * @param id                  the ID of the authorization detail DTO.
     * @param typeId              the type ID of the authorization detail.
     * @param authorizationDetail the authorization detail object.
     * @param tenantId            the tenant ID.
     */
    public AuthorizationDetailsDTO(final String id, final String typeId, final AuthorizationDetail authorizationDetail,
                                   final int tenantId) {

        this.id = id;
        this.typeId = typeId;
        this.authorizationDetail = authorizationDetail;
        this.tenantId = tenantId;
    }

    /**
     * Constructs an AuthorizationDetailsDTO from authorization detail JSON string.
     *
     * @param id                      the ID of the authorization detail DTO.
     * @param typeId                  the type ID of the authorization detail.
     * @param authorizationDetailJson the JSON string of the authorization detail.
     * @param tenantId                the tenant ID.
     */
    public AuthorizationDetailsDTO(final String id, final String typeId, final String authorizationDetailJson,
                                   final int tenantId) {

        this(id, typeId, fromJSON(authorizationDetailJson, AuthorizationDetail.class), tenantId);
    }

    /**
     * Constructs an AuthorizationDetailsDTO with an authorization detail object and tenant ID.
     *
     * @param authorizationDetail the authorization detail object.
     * @param tenantId            the tenant ID.
     */
    public AuthorizationDetailsDTO(final AuthorizationDetail authorizationDetail, final int tenantId) {

        this(null, null, authorizationDetail, tenantId);
    }

    /**
     * Gets the ID of the authorization detail.
     *
     * @return the ID of the authorization detail.
     */
    public String getId() {
        return this.id;
    }

    /**
     * Gets the type ID of the authorization detail.
     *
     * @return the type ID of the authorization detail.
     */
    public String getTypeId() {
        return this.typeId;
    }

    /**
     * Gets the authorization detail object.
     *
     * @return the authorization detail object.
     */
    public AuthorizationDetail getAuthorizationDetail() {
        return this.authorizationDetail;
    }

    /**
     * Gets the tenant ID.
     *
     * @return the tenant ID.
     */
    public int getTenantId() {
        return this.tenantId;
    }
}
