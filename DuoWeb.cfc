<cfcomponent hint="Implements Duo Security's Duo Web API">
	<cfset variables.DUO_PREFIX = "TX">
	<cfset variables.APP_PREFIX = "APP">
	<cfset variables.AUTH_PREFIX = "AUTH">
	
	<cfset variables.DUO_EXPIRE = 300>
	<cfset variables.APP_EXPIRE = 3600>
	
	<cfset variables.IKEY_LEN = 20>
	<cfset variables.SKEY_LEN = 40>
	<cfset variables.AKEY_LEN = 40>

	<cfset this.ERR_USER = "ERR|The username passed to sign_request() is invalid.">
	<cfset this.ERR_IKEY = "ERR|The Duo integration key passed to sign_request() is invalid.">
	<cfset this.ERR_SKEY = "ERR|The Duo secret key passed to sign_request() is invalid.">
	<cfset this.ERR_AKEY = "ERR|The application secret key passed to sign_request() must be at least " & AKEY_LEN & " characters.">
	<cfset this.ERR_UNKNOWN = "ERR|An unknown error has occurred.">
	
	<cffunction name="signRequest" returntype="string" output="false" access="public">
		<cfargument name="iKey" type="string" hint="Your Duo Integration Key">
		<cfargument name="sKey" type="string" hint="Your Duo Secret Key">
		<cfargument name="aKey" type="string" hint="Your Duo Application Key">
		<cfargument name="username" type="string">
		<cfset var duo_sig = "">
		<cfset var app_sig = "">
		<cfif NOT Len(arguments.username)>
			<cfreturn this.ERR_USER>
		</cfif>
		<cfif NOT Len(arguments.iKey) OR Len(arguments.iKey) NEQ variables.IKEY_LEN>
			<cfreturn this.ERR_IKEY>
		</cfif>
		<cfif NOT Len(arguments.sKey) OR Len(arguments.sKey) NEQ variables.SKEY_LEN>
			<cfreturn this.ERR_SKEY>
		</cfif>
		<cfif NOT Len(arguments.aKey) OR Len(arguments.aKey) LT variables.AKEY_LEN>
			<cfreturn this.ERR_AKEY>
		</cfif>
		<cftry>
			<cfset duo_sig = signVals(arguments.sKey, arguments.username, arguments.iKey, variables.DUO_PREFIX, variables.DUO_EXPIRE)>
			<cfset app_sig = signVals(arguments.aKey, arguments.username, arguments.iKey, variables.APP_PREFIX, variables.APP_EXPIRE)>
			<cfcatch>
				<cfreturn this.ERR_UNKNOWN>
			</cfcatch>
		</cftry>
		<cfreturn duo_sig & ":" & app_sig>
	</cffunction>
	
	
	<cffunction name="verifyResponse" returntype="string" output="false" access="public">
		<cfargument name="iKey" type="string" hint="Your Duo Integration Key">
		<cfargument name="sKey" type="string" hint="Your Duo Secret Key">
		<cfargument name="aKey" type="string" hint="Your Duo Application Key">
		<cfargument name="sig_response" type="string">
		<cfset var auth_user = "">
		<cfset var app_user = "">
		<cfset var auth_sig = "">
		<cfset var app_sig = "">
		<cftry>
			<cfif ListLen(arguments.sig_response, ":") NEQ 2>
				<cfreturn "">
			</cfif>
			<cfset auth_sig = ListFirst(arguments.sig_response, ":")>
			<cfset app_sig = ListLast(arguments.sig_response, ":")>
			<cfset auth_user = parseVals(arguments.sKey, auth_sig, variables.AUTH_PREFIX)>
			<cfset app_user = parseVals(arguments.aKey, app_sig, variables.APP_PREFIX)>
			<cfif NOT Len(auth_user) OR NOT Len(app_user) OR auth_user IS NOT app_user>
				<cfreturn "">
			</cfif>
			<cfcatch>
				<cfreturn "">
			</cfcatch>
		</cftry>
		<cfreturn auth_user>
	</cffunction>
	
	<cffunction name="signVals" returntype="string" output="false" access="public">
		<cfargument name="key" type="string">
		<cfargument name="username" type="string">
		<cfargument name="iKey" type="string">
		<cfargument name="prefix" type="string">
		<cfargument name="expire" type="numeric">
		<cfset var ts = Left(GetTickCount(), Len(GetTickCount())-3)>
		<cfset var expire_ts = ts + arguments.expire>
		<cfset var value = arguments.username & "|" & arguments.ikey & "|" & expire_ts>
		<cfset var cookie = arguments.prefix & "|" & ToBase64(value)>
		<cfset var sig = hmacSign(arguments.key, cookie)>
		<cfreturn cookie & "|" & sig>
	</cffunction>
	
	<cffunction name="parseVals" returntype="string" access="private" output="false">
		<cfargument name="key" type="string">
		<cfargument name="value" type="string">
		<cfargument name="prefix" type="string">
		<cfset var ts = Left(GetTickCount(), Len(GetTickCount())-3)>
		<cfset var u_prefix = ListFirst(arguments.value, "|")>
		<cfset var u_b64 = ListGetAt(arguments.value, 2, "|")>
		<cfset var u_sig = ListGetAt(arguments.value, 3, "|")>
		<cfset var sig = hmacSign(arguments.key, u_prefix & "|" & u_b64)>
		<cfset var cookie = "">
		<cfset var username = "">
		<cfset var expire = "">
		<cfif hmacSign(arguments.key, LCase(sig)) IS NOT hmacSign(arguments.key, LCase(u_sig))>
			<cfreturn "">
		</cfif>
		<cfif u_prefix IS NOT arguments.prefix>
			<cfreturn "">
		</cfif>
		<cftry>
			<cfset cookie = ToString(ToBinary(u_b64))>
			<cfcatch>
				<!--- toBinary throws exception if not base64 string --->
				<cfreturn "">
			</cfcatch>
		</cftry>
		<cfif ListLen(cookie, "|") LT 3>
			<cfreturn "">
		</cfif>
		
		<cfset username = Trim(ListFirst(cookie, "|"))>
		<cfset expire = Trim(ListGetAt(cookie, 3, "|"))>
		<cfif ts GTE Val(expire)>
			<cfreturn "">
		</cfif>
		<cfreturn username>
	</cffunction>
	
	
	<cffunction name="hmacSign" returntype="string" access="public" output="false">
   		<cfargument name="key" type="string" required="true" />
   		<cfargument name="message" type="string" required="true" />
		<cfset var keySpec = createObject("java","javax.crypto.spec.SecretKeySpec") />
		<cfset var mac = createObject("java","javax.crypto.Mac") />
		<cfset var keyBytes = JavaCast("string", arguments.key).getBytes()>
		<cfset keySpec = keySpec.init(keyBytes,"HmacSHA1") />
		<cfset mac = mac.getInstance(keySpec.getAlgorithm()) />
		<cfset mac.init(keySpec) />
		<cfset mac.update(arguments.message.getBytes()) />
		<cfreturn LCase(BinaryEncode(mac.doFinal(), "Hex")) />
	</cffunction>

	
	
</cfcomponent>
