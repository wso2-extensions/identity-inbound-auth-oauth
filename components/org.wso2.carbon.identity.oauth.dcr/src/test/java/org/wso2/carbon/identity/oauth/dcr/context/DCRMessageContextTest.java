package org.wso2.carbon.identity.oauth.dcr.context;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.testng.Assert.assertNotNull;

public class DCRMessageContextTest {

    private DCRMessageContext dcrMessageContext;
    private IdentityRequest mockIdentityRequet;
    @Test
    public void testGetIdentityRequest() throws Exception {
        mockIdentityRequet = mock(IdentityRequest.class);
        dcrMessageContext = new DCRMessageContext(mockIdentityRequet);
        assertNotNull(dcrMessageContext.getIdentityRequest());
    }
}
