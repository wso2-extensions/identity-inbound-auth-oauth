package org.wso2.carbon.identity.test.common.mock;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

/**
 * A mock authenticated user can be used for unit tests.
 */
public class MockAuthenticatedUser extends AuthenticatedUser {

    public MockAuthenticatedUser(String userName) {
        this.userName = userName;
    }

    @Override
    public String toString() {
        return userName;
    }

}
