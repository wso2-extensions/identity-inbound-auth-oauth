package org.wso2.carbon.identity.oauth.endpoint.ciba;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailedException;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;

import java.nio.file.Paths;

@PrepareForTest({CibaParams.class, CibaDAOFactory.class, AuthzRequestDTO.class, CibaAuthRequestDTO.class,
        CibaAuthResponseDTO.class, CibaCoreException.class, ErrorCodes.class, CibaAuthCodeDO.class, CibaAuthUtil.class,
        CibaAuthFailedException.class, JWT.class,})
public class CibaAuthReqValidatorTest extends TestOAuthEndpointBase {

    @Mock
    CibaAuthRequestValidator cibaAuthRequestValidator;
    private static final String request = "eyJhbGciOiJIUzUxMiJ9" +
            ".eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6IjE5MDgxOTk1IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGVuaWQgc21zIiwiaWF0IjoxNTczMDk5NDEzLCJleHAiOjE1NzMxNDQzNzEsIm5iZiI6MTU3MzA5OTQxMywianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwicmVxdWVzdGVkX2V4cGlyeSI6MzcwMH0.dcyX4dNaI-u0maButJ4h3q383OnDXCPMzgHzpU3ZHxsjlGIC_I-B_3QApMnQCav8-cSaYv62FWTqoUOF9wf4yw";

    @Mock
    CibaAuthRequestDTO cibaAuthRequestDTO;

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        cibaAuthRequestValidator = CibaAuthRequestValidator.getInstance();

        Class<?> clazz = CibaAuthRequestValidator.class;
    }

    @DataProvider(name = "provideRequestParams")
    public Object[][] provideRequestParams() {

        return new Object[][]{
                {request + "frsgtg.ftetryyru"},
                {"eftaeg"},
                {"etfcra.cesavr"},
                {"vrsgyb.waygersh.reygsrab"},
                {""},
        };

    }


    @Test(dataProvider = "provideRequestParams", expectedExceptions = {CibaAuthFailedException.class,
            java.text.ParseException.class})
    public void testValidateAudience(String request) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        cibaAuthRequestValidator.validateAudience(claimsSet,cibaAuthRequestDTO);

    }
}