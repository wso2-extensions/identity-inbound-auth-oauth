package org.wso2.carbon.identity.oauth.endpoint.authzchallenge.model;

import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.NextStep;

public class AuthzChallengeIncompleteResponse  extends AuthzChallengeGenericResponse {
    private NextStep nextStep;

    public AuthzChallengeIncompleteResponse() {

    }

    public AuthzChallengeIncompleteResponse(String authSession, String error, String errorDescription,
                                            NextStep nextStep) {
        super(authSession, error, errorDescription);
        this.nextStep = nextStep;
    }

    public NextStep getNextStep() {
        return nextStep;
    }

    public void setNextStep(NextStep nextStep) {
        this.nextStep = nextStep;
    }

}
