package org.wso2.carbon.identity.oauth2.rar.dto;

import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;

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
