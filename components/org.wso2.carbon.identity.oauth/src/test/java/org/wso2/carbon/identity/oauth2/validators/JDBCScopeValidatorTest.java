package org.wso2.carbon.identity.oauth2.validators;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import static org.testng.Assert.assertEquals;


/**
 * Tests JDBCScopeValidator.
 */
public class JDBCScopeValidatorTest {

    private JDBCScopeValidator validator;

    @BeforeTest
    public void setUp() {
        validator = new JDBCScopeValidator();
    }

    @Test(dataProvider = "validatingDOs")
    public void testValidateScope(AccessTokenDO accessTokenDO, String scope, boolean expectedResult) throws Exception {
        boolean result = validator.validateScope(accessTokenDO, scope);
        assertEquals(result, expectedResult);
    }


    @DataProvider(name = "validatingDOs")
    public Object[][] createValidateTokenDo() {

        AccessTokenDO accessTokenDO = new AccessTokenDO();

        return new Object[][]{
                {accessTokenDO, "scope1", true}
        };
    }

}
