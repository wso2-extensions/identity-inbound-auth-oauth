package org.wso2.carbon.identity.oauth2.model;

import java.util.List;

/**
 * OAuth scope user consent service response object.
 */
public class OAuth2ScopeConsentResponse {

    private String userId;
    private String appId;
    private int tenantId;
    private List<String> approvedScopes;
    private List<String> disapprovedScopes;

    public OAuth2ScopeConsentResponse(String userId, String appId, int tenantId, List<String> approvedScopes,
                                      List<String> disapprovedScopes) {

        this.userId = userId;
        this.appId = appId;
        this.tenantId = tenantId;
        this.approvedScopes = approvedScopes;
        this.disapprovedScopes = disapprovedScopes;
    }

    public OAuth2ScopeConsentResponse(String userId, String appId, int tenantId, List<String> approvedScopes) {

        new OAuth2ScopeConsentResponse(userId, appId, tenantId, approvedScopes, null);
    }

    public String getAppId() {

        return appId;
    }

    public String getUserId() {

        return userId;
    }

    public int getTenantId() {

        return tenantId;
    }

    public List<String> getApprovedScopes() {

        return approvedScopes;
    }

    public List<String> getDisapprovedScopes() {

        return disapprovedScopes;
    }
}
