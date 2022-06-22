<!--
~    Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
~
~    This software is the property of WSO2 Inc. and its suppliers, if any.
~    Dissemination of any information or reproduction of any material contained
~    herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
~    You may not alter or remove any copyright or other notice from copies of this content."
-->

<html>
<body onload="javascript:document.getElementById('oauth-response').submit()">
        <p> 
            <a href="javascript:document.getElementById('oauth-response').submit()">Click here</a>
            if you have been waiting for too long.
        </p>
        <form id="oauth-response" method="post" action="${redirectURI}">
        <% String params = (String) request.getAttribute("params"); %>
        <%= params %>
        </form>
</body>
</html> 
