package org.wso2.carbon.identity.oauth2.rar.common.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.common.util.AuthorizationDetailsCommonUtils;

/**
 *
 */
public class AuthorizationDetailsDTO {

    final String id;
    final int typeId;
    final AuthorizationDetail authorizationDetail;
    final int tenantId;

    public AuthorizationDetailsDTO(final String id, final int typeId, final AuthorizationDetail authorizationDetail,
                                   final int tenantId) {

        this.id = id;
        this.typeId = typeId;
        this.authorizationDetail = authorizationDetail;
        this.tenantId = tenantId;
    }

    public AuthorizationDetailsDTO(final String id, final int typeId, final String authorizationDetailJson,
                                   final int tenantId) {

        this(id, typeId, AuthorizationDetailsCommonUtils
                .fromJSON(authorizationDetailJson, AuthorizationDetail.class, new ObjectMapper()), tenantId);
    }

    public AuthorizationDetailsDTO(final AuthorizationDetail authorizationDetail, final int tenantId) {

        this(null, 0, authorizationDetail, tenantId);
    }

    public String getId() {
        return this.id;
    }

    public int getTypeId() {
        return this.typeId;
    }

    public AuthorizationDetail getAuthorizationDetail() {
        return this.authorizationDetail;
    }

    public int getTenantId() {
        return this.tenantId;
    }
}
