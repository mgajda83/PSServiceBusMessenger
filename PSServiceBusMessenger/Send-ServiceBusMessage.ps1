Function Send-ServiceBusMessage
{
	<#
	.SYNOPSIS
		Send message to ServiceBus queue.

	.PARAMETER ConnectionString
		ConnectionString to service us queue.

	.PARAMETER EndpointHost
		Host name uri to Service Bus.

	.PARAMETER EntityPath
		EntityPath to the Service Bus queue.

	.PARAMETER AccessToken
		AccessToken for authenticating with Service Bus. Requires assigning a role: Azure Service Bus Data Owner or Azure Service Bus Data Sender.

	.PARAMETER TokenValidTimeOut
		Token timeout.

	.PARAMETER MessageBody
		Message object that will be convert to json.

	.PARAMETER BrokerProperties
		Message Headers and Properties.

	.EXAMPLE
		$MessageBody = @{MessageContent = "Test"}
		Send-ServiceBusMessage -ConnectionString $ConnectionString -MessageBody $MessageBody

	.EXAMPLE
		$MessageBody = @{MessageContent = "Test"}
		$BrokerProperties =  @{ ScheduledEnqueueTimeUtc=(Get-date).AddMinutes(15).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
		Send-ServiceBusMessage -ConnectionString $ConnectionString -MessageBody $MessageBody -BrokerProperties $BrokerProperties

	.LINK
		https://learn.microsoft.com/en-us/rest/api/servicebus/message-headers-and-properties

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
		[Parameter(Mandatory=$true)]
		$MessageBody,
		[Parameter()]
		$BrokerProperties
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
		if($MessageBody -is [String])
		{
			$Body = $MessageBody
		} else {
			$Body = ($MessageBody | ConvertTo-Json -Depth 10 -Compress)
		}

		if($null -ne $BrokerProperties)
		{
			$Headers['BrokerProperties'] = $BrokerProperties | ConvertTo-Json -Compress
		}

		$Uri = "https://$($EndpointHost)/$EntityPath/messages"
		Write-Verbose $Uri

		$Params = @{
			Uri = $Uri
			ContentType = "text/plain;charset=utf-8"
			Method = "POST"
			Headers = $Headers
			Body = $Body
		}

		$Result = Invoke-RestMethod @Params

		Return $Result
	}

	End {}
}
