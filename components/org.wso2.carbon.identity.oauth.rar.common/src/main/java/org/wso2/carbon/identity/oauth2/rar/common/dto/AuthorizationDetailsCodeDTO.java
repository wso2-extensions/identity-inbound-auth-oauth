package org.wso2.carbon.identity.oauth2.rar.common.dto;

import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;

/**
 *
 */
public class AuthorizationDetailsCodeDTO extends AuthorizationDetailsDTO {

    final String codeId;

    public AuthorizationDetailsCodeDTO(final String id, final String codeId, final int typeId,
                                       final AuthorizationDetail authorizationDetail, final int tenantId) {

        super(id, typeId, authorizationDetail, tenantId);
        this.codeId = codeId;
    }

    public String getCodeId() {
        return codeId;
    }
}
