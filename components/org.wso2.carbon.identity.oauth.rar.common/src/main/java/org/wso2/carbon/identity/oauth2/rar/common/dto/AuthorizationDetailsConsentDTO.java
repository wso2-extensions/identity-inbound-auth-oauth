package org.wso2.carbon.identity.oauth2.rar.common.dto;

import org.wso2.carbon.identity.oauth2.rar.common.model.AuthorizationDetail;

/**
 *
 */
public class AuthorizationDetailsConsentDTO extends AuthorizationDetailsDTO {

    final String consentId;
    final boolean isConsentActive;

    public AuthorizationDetailsConsentDTO(final String id, final String consentId, final int typeId,
                                          final String authorizationDetail,
                                          final boolean isConsentActive, final int tenantId) {

        super(id, typeId, authorizationDetail, tenantId);
        this.consentId = consentId;
        this.isConsentActive = isConsentActive;
    }

    public AuthorizationDetailsConsentDTO(final String consentId,
                                          final AuthorizationDetail authorizationDetail,
                                          final boolean isConsentActive, final int tenantId) {

        super(authorizationDetail, tenantId);
        this.consentId = consentId;
        this.isConsentActive = isConsentActive;
    }

    public boolean isConsentActive() {
        return isConsentActive;
    }

    public String getConsentId() {
        return consentId;
    }
}
