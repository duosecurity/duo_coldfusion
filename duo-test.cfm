<cfset IKEY = "DIXXXXXXXXXXXXXXXXXX">
<cfset WRONG_IKEY = "DIXXXXXXXXXXXXXXXXXY">
<cfset SKEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef">
<cfset AKEY = "useacustomerprovidedapplicationsecretkey">

<cfset USER = "testuser">

<!--- Dummy response signatures --->
<cfset INVALID_RESPONSE = "AUTH|INVALID|SIG">
<cfset EXPIRED_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702">
<cfset FUTURE_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MjI0NzE0MDkyMQ==|d5fa72f8ba5f3d37d70dad615ff4901a77d46989">
<cfset WRONG_PARAMS_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|6cdbec0fbfa0d3f335c76b0786a4a18eac6cdca7">
<cfset WRONG_PARAMS_APP = "APP|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|7c2065ea122d028b03ef0295a4b4c5521823b9b5">

<h2>Test signRequest()</h2>
<cfset DuoWeb = CreateObject("component", "DuoWeb")>

<cfset request_sig = DuoWeb.signRequest(IKEY, SKEY, AKEY, USER)>
<cfif NOT Len(request_sig)>
	<p>FAIL request_sig was NULL</p>
<cfelse>
	<p>PASS request_sig was not NULL</p>
</cfif>

<cfset request_sig = DuoWeb.signRequest(IKEY, SKEY, AKEY, "")>
<cfif request_sig IS DuoWeb.ERR_USER>
	<p>PASS request_sig is ERR_USER</p>
<cfelse>
	<p>FAIL request_sig is not ERR_USER it is: <cfoutput>#request_sig#</cfoutput></p>
</cfif>

<cfset request_sig = DuoWeb.signRequest(IKEY, SKEY, AKEY, "in|valid")>
<cfif request_sig IS DuoWeb.ERR_USER>
	<p>PASS request_sig is ERR_USER</p>
<cfelse>
	<p>FAIL request_sig is not ERR_USER it is: <cfoutput>#request_sig#</cfoutput></p>
</cfif>

<cfset request_sig = DuoWeb.signRequest("invalid", SKEY, AKEY, USER)>
<cfif request_sig IS DuoWEb.ERR_IKEY>
	<p>PASS request_sig is ERR_IKEY</p>
<cfelse>
	<p>FAIL request_sig is not ERR_IKEY it is:<cfoutput>#request_sig#</cfoutput></p>
</cfif>


<cfset request_sig = DuoWeb.signRequest(IKEY, "invalid", AKEY, USER)>
<cfif request_sig IS DuoWeb.ERR_SKEY>
	<p>PASS request_sig is ERR_SKEY</p>
<cfelsE>
	<p>FAIL request_sig is not ERR_SKEY it is: <cfoutput>#request_sig#</cfoutput></p>
</cfif>


<cfset request_sig = DuoWeb.signRequest(IKEY, SKEY, "invalid", USER)>
<cfif request_sig IS DuoWeb.ERR_AKEY>
	<p>PASS request_sig is ERR_AKEY</p>
<cfelse>
	<p>FAIL request_sig is not ERR_AKEY</p>
</cfif>

<h2>Test verifyResponse()</h2>



<cfset request_sig = DuoWeb.signRequest(IKEY, SKEY, AKEY, USER)>

<cfset valid_app_sig = ListGetAt(request_sig, 2, ":")>


<cfset future_user = DuoWeb.verifyResponse(IKEY, SKEY, AKEY, FUTURE_RESPONSE & ":" & valid_app_sig)>
<cfif future_user IS USER>
	<p>PASS future_user</p>
<cfelse>
	<p>FAIL future_user is: <cfoutput>#future_user#</cfoutput></p>
</cfif>

<cfset request_sig = DuoWeb.signRequest(IKEY, SKEY, "1234567890123456789012345678901234567890", USER)>
<cfset invalid_app_sig = ListGetAt(request_sig, 2, ":")>

<cfset invalid_user = DuoWeb.verifyResponse(IKEY, SKEY, AKEY, INVALID_RESPONSE & ":" & valid_app_sig)>
<cfif NOT Len(invalid_user)>
	<p>PASS invalid_user</p>
<cfelse>
	<p>FAIL invalid_user</p>
</cfif>


<cfset expired_user = DuoWeb.verifyResponse(IKEY, SKEY, AKEY, EXPIRED_RESPONSE & ":" & valid_app_sig)>
<cfif NOT Len(expired_user)>
	<p>PASS expired_user</p>
<cfelse>
	<p>FAIL expired_user</p>
</cfif>


<cfset future_user = DuoWeb.verifyResponse(IKEY, SKEY, AKEY, FUTURE_RESPONSE & ":" & invalid_app_sig)>
<cfif NOT Len(future_user)>
	<p>PASS future_user invalid_app_sig</p>
<cfelse>
	<p>FAIL future_user invalid_app_sig</p>
</cfif>

<cfset future_user = DuoWeb.verifyResponse(IKEY, SKEY, AKEY, WRONG_PARAMS_RESPONSE & ":" & valid_app_sig)>
<cfif NOT Len(future_user)>
	<p>PASS future_user invalid_response_format</p>
<cfelse>
	<p>FAIL future_user invalid_response_format</p>
</cfif>

<cfset future_user = DuoWeb.verifyResponse(IKEY, SKEY, AKEY, FUTURE_RESPONSE & ":" & WRONG_PARAMS_APP)>
<cfif NOT Len(future_user)>
	<p>PASS future_user invalid_app_format</p>
<cfelse>
	<p>FAIL future_user invalid_app_format</p>
</cfif>

<cfset future_user = DuoWeb.verifyResponse(WRONG_IKEY, SKEY, AKEY, FUTURE_RESPONSE & ":" & valid_app_sig)>
<cfif NOT Len(future_user)>
	<p>PASS future_user wrong_ikey</p>
<cfelse>
	<p>FAIL future_user wrong_ikey</p>
</cfif>


<h2>Test hmacSign</h2>
<!--- test from rfc 2202 --->
<cfset result = DuoWeb.hmacSign("Jefe", "what do ya want for nothing?")>
<cfif result IS NOT "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79">
	<p>FAIL hmac result was <cfoutput>#result#</cfoutput></p>
<cfelse>
	<p>PASS hmac working properly</p>
</cfif>
