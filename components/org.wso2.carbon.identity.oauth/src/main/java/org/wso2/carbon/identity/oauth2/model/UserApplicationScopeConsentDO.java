package org.wso2.carbon.identity.oauth2.model;

import java.util.Collections;
import java.util.List;

/**
 * OAuth scope user consent data object.
 */
public class UserApplicationScopeConsentDO {

    private String appId;
    private List<String> approvedScopes;
    private List<String> disapprovedScopes;


    public UserApplicationScopeConsentDO(String appId, List<String> approvedScopes, List<String> disapprovedScopes) {

        this.appId = appId;
        setApprovedScopes(approvedScopes);
        setDisapprovedScopes(disapprovedScopes);
    }

    public UserApplicationScopeConsentDO(String appId) {

        this.appId = appId;
        this.disapprovedScopes = Collections.emptyList();
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

    public List<String> getDisapprovedScopes() {

        return disapprovedScopes;
    }

    public void setDisapprovedScopes(List<String> disapprovedScopes) {

        if (disapprovedScopes == null) {
            this.disapprovedScopes = Collections.emptyList();
        } else {
            this.disapprovedScopes = disapprovedScopes;
        }
    }
}
