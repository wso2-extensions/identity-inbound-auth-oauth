package org.wso2.carbon.identity.oauth.endpoint.device;

import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;

import java.nio.file.Paths;

import static org.testng.Assert.assertEquals;

public class DeviceEndpointTest {

    private DeviceEndpoint deviceEndpoint;

    @BeforeTest
    public void setUp() {

        System.setProperty(CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString());
        deviceEndpoint = new DeviceEndpoint();
    }

    @AfterTest
    public void cleanData() {

    }

    @DataProvider(name = "provideValues")
    public Object[][] provideValues() {

        long value1 = 1000;
        return new Object[][]{
                {value1}
        };
    }

    @Test(dataProvider = "provideValues")
    public void testStringValueInSeconds(long value) throws Exception {

        String realValue = "1";
        assertEquals(WhiteboxImpl.invokeMethod(deviceEndpoint, "stringValueInSeconds", value), realValue);
    }
}
