Function Receive-ServiceBusMessage
{
	<#
	.SYNOPSIS
		Receive message from ServiceBus queue.

	.PARAMETER ConnectionString
		ConnectionString to service us queue.

	.PARAMETER EndpointHost
		Host name uri to Service Bus.

	.PARAMETER EntityPath
		EntityPath to the Service Bus queue.

	.PARAMETER AccessToken
		AccessToken for authenticating with Service Bus. Requires assigning a role: Azure Service Bus Data Owner, Azure Service Bus Data Sender or Azure Service Bus Data Receiver.

	.PARAMETER TokenValidTimeOut
		Token timeout.

	.PARAMETER Mode
		Receive mode: PeekAndLock or ReceiveAndDelete (default).

	.PARAMETER Detailed
		Get additional BrokerProperties.

	.EXAMPLE
		$Params = @{
			Scope = @("https://servicebus.azure.net/.default")
			ClientId = $Connection.ApplicationId
			TenantId = $Connection.TenantId
			RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
			Certificate = $Certificate
		}
		$Token = Get-PSMSALToken @Params
		Receive-ServiceBusMessage -EndpointHost <ServiceBusHostUri> -EntityPath <ServiceBusQueueName> -AccessToken $Token.AccessToken

	.EXAMPLE
		Receive-ServiceBusMessage -ConnectionString $ConnectionString

	.EXAMPLE
		Receive-ServiceBusMessage -ConnectionString $ConnectionString -Mode PeekAndLock -Detailed

	.LINK
		https://learn.microsoft.com/en-us/rest/api/servicebus/receive-and-delete-message-destructive-read
		https://learn.microsoft.com/en-us/rest/api/servicebus/peek-lock-message-non-destructive-read

	.NOTES
		Author: Michal Gajda
	#>
	[CmdletBinding(SupportsShouldProcess,
		ConfirmImpact='High',
		DefaultParameterSetName="OAuth")]
	param (
		[Parameter(Mandatory=$true, ParameterSetName="ConnectionString")]
		[String]$ConnectionString,
		[Parameter(Mandatory=$true, ParameterSetName="OAuth")]
		[String]$EndpointHost,
		[Parameter(Mandatory=$true, ParameterSetName="OAuth")]
		[String]$EntityPath,
		[Parameter(Mandatory=$true, ParameterSetName="OAuth")]
		[String]$AccessToken,
		[Parameter()]
		[int]$TokenValidTimeOut,
		[Parameter()]
		[ValidateSet("PeekAndLock","ReceiveAndDelete")]
		[String]$Mode="ReceiveAndDelete",
		[Parameter()]
		[Switch]$Detailed
	)

	Begin
	{
		if($EndpointHost -and $EntityPath -and $AccessToken)
		{
			#Use OAuth token
			$Headers = @{
				Authorization = "Bearer $($AccessToken)"
			}
		} elseif($ConnectionString -match "Endpoint=(?'Endpoint'.+);SharedAccessKeyName=(?'SharedAccessKeyName'.+);SharedAccessKey=(?'SharedAccessKey'.+);EntityPath=(?'EntityPath'.+)"){
			#Load assembly
			Add-Type -AssemblyName System.Web

			#Parse connection string
			[uri]$Endpoint = $Matches['Endpoint']
			$SharedAccessKeyName = $Matches['SharedAccessKeyName']
			$SharedAccessKey = $Matches['SharedAccessKey']
			$EntityPath = $Matches['EntityPath']

			$UrlEncodedEndpoint = [System.Web.HttpUtility]::UrlEncode($Endpoint.OriginalString)
			$TokenExpiry = [DateTimeOffset]::Now.ToUnixTimeSeconds() + $TokenValidTimeOut
			$RawSignatureString = "$UrlEncodedEndpoint`n$TokenExpiry"

			$Cryptography = New-Object System.Security.Cryptography.HMACSHA256
			$Cryptography.Key = [Text.Encoding]::ASCII.GetBytes($SharedAccessKey)
			$HashBytes = $Cryptography.ComputeHash([Text.Encoding]::ASCII.GetBytes($RawSignatureString))
			$SignatureString = [Convert]::ToBase64String($HashBytes)
			$UrlEncodedSignatureString = [System.Web.HttpUtility]::UrlEncode($SignatureString)

			$SASToken = "SharedAccessSignature sig=$UrlEncodedSignatureString&se=$TokenExpiry&skn=$SharedAccessKeyName&sr=$UrlEncodedEndpoint"

			$EndpointHost = $Endpoint.Host
			$Headers = @{
				Authorization = $SASToken
			}
		}

		if($null -eq $Headers)
		{
			Write-Error -Message "Authorization header missing" -ErrorAction Stop
		}
	}

	Process
	{
		switch($Mode)
		{
			"PeekAndLock" { $Method = "POST"; break }           #Peek-Lock Message (Non-Destructive Read)
			"ReceiveAndDelete" { $Method = "DELETE"; break }    #Receive and Delete Message (Destructive Read)

		}

		$Uri = "https://$($EndpointHost)/$EntityPath/messages/head"
		Write-Verbose $Uri

		$Params = @{
			Uri = $Uri
			ContentType = "text/plain;charset=utf-8"
			Method = $Method
			Headers = $Headers
		}

		if($Detailed)
		{
			$ResultTmp = Invoke-WebRequest @Params
			if($ResultTmp.StatusCode -eq 201)
			{
				$BrokerProperties = $ResultTmp.Headers.BrokerProperties | ConvertFrom-Json
				$Result = $ResultTmp.Content | ConvertFrom-Json
				$Result | Add-Member -MemberType NoteProperty -Name BrokerProperties -Value $BrokerProperties
			} else { Write-Verbose "No message received." }
		} else {
			$Result = Invoke-RestMethod @Params
		}

		Return $Result
	}

	End {}
}
