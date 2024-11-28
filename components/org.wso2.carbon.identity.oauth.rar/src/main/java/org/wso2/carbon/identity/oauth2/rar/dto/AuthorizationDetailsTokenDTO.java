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
