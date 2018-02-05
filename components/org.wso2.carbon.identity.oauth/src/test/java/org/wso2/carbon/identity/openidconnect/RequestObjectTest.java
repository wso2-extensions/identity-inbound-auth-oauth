/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect;

public class RequestObjectTest {

    private String requestJson = "{\n" +
            "  \"iss\": \"s6BhdRkqt3\",\n" +
            "  \"aud\": \"https://server.example.com\",\n" +
            "  \"response_type\": \"code id_token\",\n" +
            "  \"client_id\": \"s6BhdRkqt3\",\n" +
            "  \"redirect_uri\": \"https://client.example.org/cb\",\n" +
            "  \"scope\": \"openid\",\n" +
            "  \"state\": \"af0ifjsldkj\",\n" +
            "  \"nonce\": \"n-0S6_WzA2Mj\",\n" +
            "  \"max_age\": 86400,\n" +
            "  \"claims\": {\n" +
            "    \"userinfo\": {\n" +
            "      \"given_name\": {\n" +
            "        \"essential\": true\n" +
            "      },\n" +
            "      \"nickname\": null,\n" +
            "      \"email\": {\n" +
            "        \"essential\": true\n" +
            "      },\n" +
            "      \"email_verified\": {\n" +
            "        \"essential\": true\n" +
            "      },\n" +
            "      \"picture\": null\n" +
            "    },\n" +
            "    \"id_token\": {\n" +
            "      \"gender\": null,\n" +
            "      \"birthdate\": {\n" +
            "        \"essential\": true\n" +
            "      },\n" +
            "      \"acr\": {\n" +
            "        \"values\": [\n" +
            "          \"urn:mace:incommon:iap:silver\"\n" +
            "        ]\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}\n";

    private String encodeRequestObject = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KICJpc3MiOiA\n" +
            "    iczZCaGRSa3F0MyIsDQogImF1ZCI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmN\n" +
            "    vbSIsDQogInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsDQogImNsaWV\n" +
            "    udF9pZCI6ICJzNkJoZFJrcXQzIiwNCiAicmVkaXJlY3RfdXJpIjogImh0dHBzOi8\n" +
            "    vY2xpZW50LmV4YW1wbGUub3JnL2NiIiwNCiAic2NvcGUiOiAib3BlbmlkIiwNCiA\n" +
            "    ic3RhdGUiOiAiYWYwaWZqc2xka2oiLA0KICJub25jZSI6ICJuLTBTNl9XekEyTWo\n" +
            "    iLA0KICJtYXhfYWdlIjogODY0MDAsDQogImNsYWltcyI6IA0KICB7DQogICAidXN\n" +
            "    lcmluZm8iOiANCiAgICB7DQogICAgICJnaXZlbl9uYW1lIjogeyJlc3NlbnRpYWw\n" +
            "    iOiB0cnVlfSwNCiAgICAgIm5pY2tuYW1lIjogbnVsbCwNCiAgICAgImVtYWlsIjo\n" +
            "    geyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgImVtYWlsX3ZlcmlmaWVkIjogeyJ\n" +
            "    lc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgInBpY3R1cmUiOiBudWxsDQogICAgfSw\n" +
            "    NCiAgICJpZF90b2tlbiI6IA0KICAgIHsNCiAgICAgImdlbmRlciI6IG51bGwsDQo\n" +
            "    gICAgICJiaXJ0aGRhdGUiOiB7ImVzc2VudGlhbCI6IHRydWV9LA0KICAgICAiYWN\n" +
            "    yIjogeyJ2YWx1ZXMiOiBbInVybjptYWNlOmluY29tbW9uOmlhcDpzaWx2ZXIiXX0\n" +
            "    NCiAgICB9DQogIH0NCn0.nwwnNsk1-ZkbmnvsF6zTHm8CHERFMGQPhos-EJcaH4H\n" +
            "    h-sMgk8ePrGhw_trPYs8KQxsn6R9Emo_wHwajyFKzuMXZFSZ3p6Mb8dkxtVyjoy2\n" +
            "    GIzvuJT_u7PkY2t8QU9hjBcHs68PkgjDVTrG1uRTx0GxFbuPbj96tVuj11pTnmFC\n" +
            "    UR6IEOXKYr7iGOCRB3btfJhM0_AKQUfqKnRlrRscc8Kol-cSLWoYE9l5QqholImz\n" +
            "    jT_cMnNIznW9E7CDyWXTsO70xnB4SkG6pXfLSjLLlxmPGiyon_-Te111V8uE83Il\n" +
            "    zCYIb_NMXvtTIVc1jpspnTSD7xMbpL-2QgwUsAlMGzw\n";

    private String encryptedRequestObject = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.K52jFwAQJH-\n" +
            "DxMhtaq7sg5tMuot_mT5dm1DR_01wj6ZUQQhJFO02vPI44W5nDjC5C_v4p\n" +
            "W1UiJa3cwb5y2Rd9kSvb0ZxAqGX9c4Z4zouRU57729ML3V05UArUhck9Zv\n" +
            "ssfkDW1VclingL8LfagRUs2z95UkwhiZyaKpmrgqpKX8azQFGNLBvEjXnx\n" +
            "-xoDFZIYwHOno290HOpig3aUsDxhsioweiXbeLXxLeRsivaLwUWRUZfHRC\n" +
            " _HGAo8KSF4gQZmeJtRgai5mz6qgbVkg7jPQyZFtM5_ul0UKHE2y0AtWm8I\n" +
            " zDE_rbAV14OCRZJ6n38X5urVFFE5sdphdGsNlA.gjI_RIFWZXJwaO9R.oa\n" +
            " E5a-z0N1MW9FBkhKeKeFa5e7hxVXOuANZsNmBYYT8G_xlXkMD0nz4fIaGt\n" +
            "uWd3t9Xp-kufvvfD-xOnAs2SBX_Y1kYGPto4mibBjIrXQEjDsKyKwndxzr\n" +
            "utN9csmFwqWhx1sLHMpJkgsnfLTi9yWBPKH5Krx23IhoDGoSfqOquuhxn0\n" +
            "y0WkuqH1R3z-fluUs6sxx9qx6NFVS1NRQ-LVn9sWT5yx8m9AQ_ng8MBWz2\n" +
            "BfBTV0tjliV74ogNDikNXTAkD9rsWFV0IX4IpA.sOLijuVySaKI-FYUaBy\n" +
            "wpg";

    public String getEncryptedRequestObject() {
        return encryptedRequestObject;
    }

    public String getEncodeRequestObject() {
        return encodeRequestObject;
    }

    public String getRequestJson() {
        return requestJson;
    }
}