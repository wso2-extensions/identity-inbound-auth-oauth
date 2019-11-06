package org.wso2.carbon.identity.oauth2.device.grant;

import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
public class DeviceFlowGrantTest extends PowerMockTestCase {

    private HashMap<String, String> results = new HashMap<>();
    private HashMap<String, String> results1 = new HashMap<>();
    private Date date = new Date();
    private Timestamp newTime = new Timestamp(date.getTime());

    @BeforeTest
    public void setUp() throws Exception {

        results.put(Constants.EXPIRY_TIME,String.valueOf(date.getTime()-1000));
        results.put(Constants.LAST_POLL_TIME,String.valueOf(new Timestamp(date.getTime()-1000)));
        results.put(Constants.POLL_TIME,String.valueOf(1500));
        results1.put(Constants.EXPIRY_TIME,String.valueOf(date.getTime()+1000));
        results1.put(Constants.LAST_POLL_TIME,String.valueOf(new Timestamp(date.getTime()-2000)));
        results1.put(Constants.POLL_TIME,String.valueOf(1500));

    }

    @AfterMethod
    public void tearDown() {
    }

    @Test
    public void testIsValidDeviceCode() throws Exception {

        Assert.assertTrue(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isValidDeviceCode",results, date));
        Assert.assertFalse(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,
                "isValidDeviceCode",results1, date));
    }

    @Test
    public void testIsValidPollTime() throws Exception {
        Assert.assertFalse(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,"isValidPollTime"
                , newTime, results));
        Assert.assertTrue(WhiteboxImpl.invokeMethod(DeviceFlowGrant.class,"isValidPollTime"
                , newTime, results1));
    }

}
