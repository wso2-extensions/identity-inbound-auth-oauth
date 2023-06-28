package org.wso2.carbon.identity.oauth.par.common;

import org.apache.axiom.om.OMElement;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;

import javax.xml.namespace.QName;

public class ParConfigResolver {

    private static final String PAR = "PAR";
    private static final IdentityConfigParser configParser = IdentityConfigParser.getInstance();
    private static final OMElement oauthElem = configParser.getConfigElement("OAuth");

    private static final OMElement parConfig = oauthElem.getFirstChildWithName(new QName(IdentityCoreConstants.
            IDENTITY_DEFAULT_NAMESPACE, PAR));

    private static final long EXPIRES_IN_VALUE = parConfig.getAttributeValue(new QName(
            PAR)) != null ? Long.parseLong(parConfig.getAttributeValue(new QName(PAR))) : 60;

    public static long getExpiresInValue() {
        return EXPIRES_IN_VALUE;
    }
}
