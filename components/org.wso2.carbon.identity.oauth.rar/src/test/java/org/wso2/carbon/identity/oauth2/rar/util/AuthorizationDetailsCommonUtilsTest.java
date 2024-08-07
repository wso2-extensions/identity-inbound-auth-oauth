package org.wso2.carbon.identity.oauth2.rar.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.testng.collections.Sets;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

/**
 * Test class for {@link AuthorizationDetailsCommonUtils}.
 */
public class AuthorizationDetailsCommonUtilsTest {

    private ObjectMapper objectMapper;
    private ObjectMapper mockObjectMapper;
    private static final String TEST_TYPE = "test_type_v1";

    @BeforeClass
    public void setUp() throws JsonProcessingException {

        this.objectMapper = AuthorizationDetailsCommonUtils.getDefaultObjectMapper();
        this.mockObjectMapper = Mockito.spy(this.objectMapper);

        // mock
        doThrow(JsonProcessingException.class)
                .when(this.mockObjectMapper).writeValueAsString(any(TestAuthorizationDetail.class));
        doThrow(JsonProcessingException.class).when(this.mockObjectMapper).writeValueAsString(any(Set.class));
    }

    @DataProvider(name = "AuthorizationDetailsCommonUtilsTestDataProvider")
    public Object[][] provideAuthorizationDetailsCommonUtilsTestData(Method testMethod) {

        switch (testMethod.getName()) {
            case "shouldReturnNull_whenJSONIsInvalid":
            case "shouldReturnCorrectSize_whenJSONArrayIsValid":
                return new Object[][]{
                        {null, 0},
                        {"", 0},
                        {" ", 0},
                        {"invalid JSON", 0},
                        {"[]", 0},
                        {"[{}]", 1},
                        {"[{},{}]", 2}
                };
            case "shouldReturnCorrectType_whenJSONIsValid":
                return new Object[][]{
                        {AuthorizationDetail.class},
                        {TestAuthorizationDetail.class}
                };
        }
        return null;
    }

    @Test(dataProvider = "AuthorizationDetailsCommonUtilsTestDataProvider")
    public void shouldReturnCorrectSize_whenJSONArrayIsValid(String inputJson, int expectedSize) {

        Set<AuthorizationDetail> actualAuthorizationDetails = AuthorizationDetailsCommonUtils
                .fromJSONArray(inputJson, AuthorizationDetail.class, objectMapper);

        assertEquals(expectedSize, actualAuthorizationDetails.size());
    }

    @Test(dataProvider = "AuthorizationDetailsCommonUtilsTestDataProvider")
    public void shouldReturnNull_whenJSONIsInvalid(String inputJson, int expectedSize) {

        assertNull(AuthorizationDetailsCommonUtils.fromJSON(inputJson, AuthorizationDetail.class, objectMapper));
    }

    @Test(dataProvider = "AuthorizationDetailsCommonUtilsTestDataProvider")
    public <T extends AuthorizationDetail> void shouldReturnCorrectType_whenJSONIsValid(Class<T> expectedClazz) {

        final String inputJson = "{\"type\": \"" + TEST_TYPE + "\"}";
        AuthorizationDetail actualAuthorizationDetail =
                AuthorizationDetailsCommonUtils.fromJSON(inputJson, expectedClazz, objectMapper);

        assertNotNull(actualAuthorizationDetail);
        assertEquals(TEST_TYPE, actualAuthorizationDetail.getType());
    }

    @Test
    public void shouldReturnCorrectJson_whenAuthorizationDetailsAreValid() {

        AuthorizationDetail inputAuthorizationDetail = new TestAuthorizationDetail();
        inputAuthorizationDetail.setType(TEST_TYPE);

        assertTrue(AuthorizationDetailsCommonUtils.toJSON(Sets.newHashSet(inputAuthorizationDetail), objectMapper)
                .contains(TEST_TYPE));
        assertEquals("[]", AuthorizationDetailsCommonUtils.toJSON((Set<AuthorizationDetail>) null, objectMapper));
        assertEquals("[]",
                AuthorizationDetailsCommonUtils.toJSON(Sets.newHashSet(inputAuthorizationDetail), mockObjectMapper));
    }

    @Test
    public void shouldReturnCorrectJson_whenAuthorizationDetailIsValid() {

        AuthorizationDetail inputAuthorizationDetail = new TestAuthorizationDetail();
        inputAuthorizationDetail.setType(TEST_TYPE);

        assertTrue(AuthorizationDetailsCommonUtils.toJSON(inputAuthorizationDetail, objectMapper).contains(TEST_TYPE));
        assertEquals("{}", AuthorizationDetailsCommonUtils.toJSON((TestAuthorizationDetail) null, objectMapper));
        assertEquals("{}", AuthorizationDetailsCommonUtils.toJSON(new TestAuthorizationDetail(), mockObjectMapper));
    }

    @Test
    public void shouldReturnMap_whenAuthorizationDetailIsValid() {

        AuthorizationDetail inputAuthorizationDetail = new TestAuthorizationDetail();
        inputAuthorizationDetail.setType(TEST_TYPE);
        Map<String, Object> actualMap = AuthorizationDetailsCommonUtils.toMap(inputAuthorizationDetail, objectMapper);

        assertTrue(actualMap.containsKey("type"));
        assertEquals(TEST_TYPE, String.valueOf(actualMap.get("type")));
        assertEquals(1, actualMap.keySet().size());

        assertFalse(AuthorizationDetailsCommonUtils.toMap(null, objectMapper).containsKey(TEST_TYPE));
    }

    private static class TestAuthorizationDetail extends AuthorizationDetail {
        // Test authorization detail class which extends AuthorizationDetail
    }
}
