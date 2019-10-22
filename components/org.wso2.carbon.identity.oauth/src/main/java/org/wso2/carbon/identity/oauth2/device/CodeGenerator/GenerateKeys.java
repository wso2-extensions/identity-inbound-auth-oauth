package org.wso2.carbon.identity.oauth2.device.CodeGenerator;

public class GenerateKeys {

    public GenerateKeys() {

    }

    public String getKey(int n) {

        String AlphaNumericString = "BCDFGHJKLMNPQRSTVWXYZ";

        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {

            // generate a random number between
            // 0 to AlphaNumericString variable length
            int index
                    = (int) (AlphaNumericString.length()
                    * Math.random());

            // add Character one by one in end of sb
            sb.append(AlphaNumericString
                    .charAt(index));
        }

        return sb.toString();
    }
}
