package org.wso2.carbon.identity.oauth2.model;

import java.util.Collections;
import java.util.List;

/**
 * OAuth scope user consent data object.
 */
public class UserApplicationScopeConsentDO {

    private String appId;
    private List<String> approvedScopes;
    private List<String> deniedScopes;


    public UserApplicationScopeConsentDO(String appId, List<String> approvedScopes, List<String> deniedScopes) {

        this.appId = appId;
        setApprovedScopes(approvedScopes);
        setDeniedScopes(deniedScopes);
    }

    public UserApplicationScopeConsentDO(String appId) {

        this.appId = appId;
        this.deniedScopes = Collections.emptyList();
        this.approvedScopes = Collections.emptyList();
    }

    public String getAppId() {

        return appId;
    }

    public void setAppId(String appId) {

        this.appId = appId;
    }

    public List<String> getApprovedScopes() {

        return approvedScopes;
    }

    public void setApprovedScopes(List<String> approvedScopes) {

        if (approvedScopes == null) {
            this.approvedScopes = Collections.emptyList();
        } else {
            this.approvedScopes = approvedScopes;
        }
    }

    public List<String> getDeniedScopes() {

        return deniedScopes;
    }

    public void setDeniedScopes(List<String> deniedScopes) {

        if (deniedScopes == null) {
            this.deniedScopes = Collections.emptyList();
        } else {
            this.deniedScopes = deniedScopes;
        }
    }
}
