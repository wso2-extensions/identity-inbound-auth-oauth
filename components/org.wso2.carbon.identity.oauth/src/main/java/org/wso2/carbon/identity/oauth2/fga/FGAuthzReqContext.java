package org.wso2.carbon.identity.oauth2.fga;

import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;

/**
 * Model class to send request context to FGA authorization implementation.
 */
public class FGAuthzReqContext {

    private String subjectId;
    //private JSONObject context;
    private ArrayList<String> requestedScopes;

    public FGAuthzReqContext(OAuthAuthzReqMessageContext authzReqMessageContext) throws UserIdNotFoundException {

        subjectId = authzReqMessageContext.getAuthorizationReqDTO().getUser().getUserId();
    }

    public FGAuthzReqContext(OAuthTokenReqMessageContext tokenReqMessageContext) throws UserIdNotFoundException {

        subjectId = tokenReqMessageContext.getAuthorizedUser().getUserId();
    }

    public String getSubjectId() {

        return subjectId;
    }

    public ArrayList<String> getRequestedScopes() {

        return requestedScopes;
    }

    public void setRequestedScopes(ArrayList<String> requestedScopes) {

        this.requestedScopes = requestedScopes;
    }
}
