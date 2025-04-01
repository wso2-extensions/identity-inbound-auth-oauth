package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;

public class AuthzChallengeIncompleteResponse  extends AuthzChallengeGenericResponse {
    private NextStep next_step;

    public AuthzChallengeIncompleteResponse() {

    }

    public AuthzChallengeIncompleteResponse(String authSession, String error, String errorDescription,
                                            NextStep nextStep) {
        super(authSession, error, errorDescription);
        this.next_step = nextStep;
    }

    public NextStep getNextStep() {
        return next_step;
    }

    public void setNextStep(NextStep nextStep) {
        this.next_step = nextStep;
    }

}
