param ($au2matorhook)
$jsondata = $au2matorhook | ConvertFrom-Json


#Environment
[string]$CredentialStorePath = "C:\_SCOworkingDir\TFS\PS-Services\CredentialStore" #see for details: https://au2mator.com/documentation/powershell-credentials/?utm_source=github&utm_medium=social&utm_campaign=PS_Template&utm_content=PS1
[string]$LogPath = "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Start a VM\LOGS"
[string]$LogfileName = "Question-GetMyVMs"


$AzureRestAPICred_File = "AzureRestCreds.xml"
$AzureRestAPICred = Import-CliXml -Path (Get-ChildItem -Path $CredentialStorePath -Filter $AzureRestAPICred_File).FullName
$AzureRestAPI_clientId = $AzureRestAPICred.clientId
$AzureRestAPI_clientSecret = $AzureRestAPICred.clientSecret
$AzureRestAPI_tenantID = $AzureRestAPICred.tenantID

$apiversion = "2022-08-01"


$InitiatedBy = $jsondata.InitiatedBy



#region Functions
function Write-au2matorLog {
    [CmdletBinding()]
    param
    (
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Type,
        [string]$Text
    )

    # Set logging path
    if (!(Test-Path -Path $logPath)) {
        try {
            $null = New-Item -Path $logPath -ItemType Directory
            Write-Verbose ("Path: ""{0}"" was created." -f $logPath)
        }
        catch {
            Write-Verbose ("Path: ""{0}"" couldn't be created." -f $logPath)
        }
    }
    else {
        Write-Verbose ("Path: ""{0}"" already exists." -f $logPath)
    }
    [string]$logFile = '{0}\{1}_{2}.log' -f $logPath, $(Get-Date -Format 'yyyyMMdd'), $LogfileName
    $logEntry = '{0}: <{1}> <{2}> <{3}> {4}' -f $(Get-Date -Format dd.MM.yyyy-HH:mm:ss), $Type, $RequestId, $Service, $Text
    Add-Content -Path $logFile -Value $logEntry
}

#endregion Functions

try {
    Write-au2matorLog -Type INFO -Text "Try to connect to Azure Rest API"
    
    $param = @{
        Uri    = "https://login.microsoftonline.com/$AzureRestAPI_tenantID/oauth2/token?api-version=$apiversion";
        Method = 'Post';
        Body   = @{ 
            grant_type    = 'client_credentials'; 
            resource      = 'https://management.core.windows.net/'; 
            client_id     = $AzureRestAPI_clientId; 
            client_secret = $AzureRestAPI_clientSecret
        }
    }
      
    $result = Invoke-RestMethod @param
    $token = $result.access_token
          
      
    $headers = @{
        "Authorization" = "Bearer $($token)"
        "Content-type"  = "application/json"
    }
    
    try {
        Write-au2matorLog -Type INFO -Text "Get Owner UPN"
        $OwnerUPN=(Get-ADUser -Identity ($InitiatedBy.split("\")[1])).userprincipalname
        Write-au2matorLog -Type INFO -Text "UPN: $OwnerUPN "

        Write-au2matorLog -Type INFO -Text "Try to get all Subscriptions"
        $URL = "https://management.azure.com/subscriptions?api-version=2022-09-01"
        $Subs = Invoke-RestMethod -Method GET -URI $URL -headers $headers 
        

        Write-au2matorLog -Type INFO -Text "found that amount of Subscriptions: $($Subs.value.count)"

        $VMList = @()
        foreach ($s in $Subs.value) {
            Write-au2matorLog -Type INFO -Text "Work with Subscription: $($S.displayName)"

            Write-au2matorLog -Type INFO -Text "Get VMs for Owner"
            $URL = "https://management.azure.com/subscriptions/$($S.SubscriptionID)/resources?`$filter=tagname eq 'Owner' and tagvalue eq '$($OwnerUPN)'&api-version=2022-09-01"

            $VMfromSub = Invoke-RestMethod -Method GET -URI $URL -headers $headers 
            foreach ($V in $VMfromSub.value) {
                $URL = "https://management.azure.com$($V.id)/instanceView?api-version=2022-08-01"
                $IView = Invoke-RestMethod -Method GET -URI $URL -headers $headers
                if (($IView.statuses | Where-Object -Property code -Value "PowerState*" -like).displayStatus -ne "VM running") {
                    $PSObject = New-Object -TypeName PSObject                    
                    $PSObject | Add-Member -MemberType NoteProperty -Name Name -Value "<b>$($V.Name)</b>"
                    $PSObject | Add-Member -MemberType NoteProperty -Name Status -Value $(($IView.statuses | Where-Object -Property code -Value "PowerState*" -like).displayStatus)
                    $VMList += $PSObject
                }
            }
        }        
    }
    catch {
        Write-au2matorLog -Type ERROR -Text "Error to get Subscriptions"
        Write-au2matorLog -Type ERROR -Text $Error
    
        $au2matorReturn = "Error to get Subscriptions, Error: $Error"
        $TeamsReturn = "Error to get Subscriptions" #No Special Characters allowed
        $AdditionalHTML = "Error to get Subscriptions
        <br>
        Error: $Error
            "
        $Status = "ERROR"
    }
}
catch {
    Write-au2matorLog -Type ERROR -Text "Failed to connect to Azure Rest API"
    Write-au2matorLog -Type ERROR -Text $Error

    $au2matorReturn = "Failed to connect to Azure Rest API, Error: $Error"
    $TeamsReturn = "Failed to connect to Azure Rest API" #No Special Characters allowed
    $AdditionalHTML = "Failed to connect to Azure Rest API
    <br>
    Error: $Error
        "
    $Status = "ERROR"
}

return $VMList