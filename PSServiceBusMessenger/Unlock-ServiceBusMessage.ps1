Function Unlock-ServiceBusMessage
{
	<#
	.SYNOPSIS
		Unlock message in ServiceBus queue.

	.PARAMETER ConnectionString
		ConnectionString to service us queue.

	.PARAMETER EndpointHost
		Host name uri to Service Bus.

	.PARAMETER EntityPath
		EntityPath to the Service Bus queue.

	.PARAMETER AccessToken
		AccessToken for authenticating with Service Bus. Requires assigning a role: Azure Service Bus Data Owner.

	.PARAMETER TokenValidTimeOut
		Token timeout.

	.PARAMETER MessageId
		Message id that will be unlock.

	.PARAMETER MessageSequenceNumber
		Message sequence number that will be unlock.

	.PARAMETER LockToken
		LockToken return in BrokerProperties. Only when used PeekAndLock option.

	.EXAMPLE
		$LockToken = $Result.BrokerProperties.LockToken
		Unlock-ServiceBusMessage -ConnectionString $ConnectionString -MessageId $MessageId -LockToken $LockToken

	.EXAMPLE
		Unlock-ServiceBusMessage -ConnectionString $ConnectionString -MessageSequenceNumber 3 -LockToken $LockToken

	.LINK
		https://learn.microsoft.com/en-us/rest/api/servicebus/unlock-message

	.NOTES
		Author: Michal Gajda
	#>
	[CmdletBinding(SupportsShouldProcess,
		ConfirmImpact='High',
		DefaultParameterSetName="OAuthMessageId")]
	param (
		[Parameter(Mandatory=$true, ParameterSetName="ConnectionStringMessageId")]
		[Parameter(Mandatory=$true, ParameterSetName="ConnectionStringMessageSequenceNumber")]
		[String]$ConnectionString,
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageId")]
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageSequenceNumber")]
		[String]$EndpointHost,
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageId")]
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageSequenceNumber")]
		[String]$EntityPath,
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageId")]
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageSequenceNumber")]
		[String]$AccessToken,
		[Parameter()]
		[int]$TokenValidTimeOut,
		[Parameter(Mandatory=$true, ParameterSetName="ConnectionStringMessageId")]
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageId")]
		[String]$MessageId,
		[Parameter(Mandatory=$true, ParameterSetName="ConnectionStringMessageSequenceNumber")]
		[Parameter(Mandatory=$true, ParameterSetName="OAuthMessageSequenceNumber")]
		[int]$MessageSequenceNumber,
		[Parameter(Mandatory=$true)]
		[String]$LockToken
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
			[Uri]$Endpoint = $Matches['Endpoint']
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
		if($PSCmdlet.MyInvocation.BoundParameters['MessageId'])
		{
			$Uri = "https://$($EndpointHost)/$EntityPath/messages/$MessageId/$LockToken"
		}
		if($PSCmdlet.MyInvocation.BoundParameters['MessageSequenceNumber'])
		{
			$Uri = "https://$($EndpointHost)/$EntityPath/messages/$MessageSequenceNumber/$LockToken"
		}
		Write-Verbose $Uri

		$Params = @{
			Uri = $Uri
			ContentType = "text/plain;charset=utf-8"
			Method = "PUT"
			Headers = $Headers
		}

		$Result = Invoke-RestMethod @Params

		Return $Result
	}

	End {}
}
