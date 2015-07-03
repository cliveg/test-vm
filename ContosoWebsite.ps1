Configuration ContosoWebsite
{
  param ($MachineName)

	Enable-CredSSPNTLM -DomainName $MachineName
	Import-DscResource -ModuleName xComputerManagement, xActiveDirectory, xDisk, xCredSSP, cDisk, xNetworking, xSystemSecurity
	 
  Node ($MachineName)
  {
            WindowsFeature ADPS
            {
                Name = "RSAT-AD-PowerShell"
                Ensure = "Present"
            }
            WindowsFeature NET-Framework-45-Core
            {
                Name = "NET-Framework-45-Core"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]ADPS"
            }
            WindowsFeature Windows-Identity-Foundation
            {
                Name = "Windows-Identity-Foundation"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]NET-Framework-45-Core"
            }
            WindowsFeature Telnet-Client
            {
                Name = "Telnet-Client"
                Ensure = "Present"
                DependsOn = "[WindowsFeature]Windows-Identity-Foundation"
            }


        xIEEsc EnableIEEscAdmin
        {
            IsEnabled = $True
            UserRole  = "Administrators"
        }

        xIEEsc EnableIEEscUser
        {
            IsEnabled = $False
            UserRole  = "Users"
        }

	Script ConfigureCPU
	{
		GetScript = {
            @{
                Result = ""
            }
        }
        TestScript = {
            $false
        }
        SetScript ={

		  # Set PowerPlan to "High Performance"
			$guid = (Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName='High Performance'").InstanceID.ToString()
			$regex = [regex]"{(.*?)}$"
			$plan = $regex.Match($guid).groups[1].value
			powercfg -S $plan
		}
	}

   #script block to download apps and install them

    Script DownloadRootCert
    {
        GetScript = {
            @{
                Result = "DownloadRootCert"
            }
        }
        TestScript = {
            Test-Path "C:\WindowsAzure\certnew.cer"
        }
        SetScript ={
            $source = "http://localhost/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Enc=bin"
            $destination = "C:\WindowsAzure\certnew.cer"
            Invoke-WebRequest $source -OutFile $destination

			#Import Certificate
			Import-Certificate -FilePath "C:\WindowsAzure\certnew.Cer" -CertStoreLocation 'Cert:\LocalMachine\Trusted Root Certification Authorities' -Verbose 
        }
    }


Script Whodis
{
    GetScript = { 
        return @{ 
            SetScript = $SetScript
            TestScript = $TestScript
            GetScript = $GetScript                
        }
    }
    TestScript = { $false } # Always execute this script -- leave it up to script to be indempotent
    SetScript = ([String]{            
        $password = ConvertTo-SecureString 'AzP@ssword1' -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential "AzAdmin",$password
        Invoke-Command { whoami } -ComputerName Localhost -EnableNetworkAccess -Credential $credential -Authentication CredSSP
    })
}



  }
} 



function Enable-CredSSPNTLM
{ 
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    # This is needed for the case where NTLM authentication is used

    Write-Verbose 'STARTED:Setting up CredSSP for NTLM'
   
    Enable-WSManCredSSP -Role client -DelegateComputer localhost, *.$DomainName -Force -ErrorAction SilentlyContinue
    Enable-WSManCredSSP -Role server -Force -ErrorAction SilentlyContinue

    if(-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -ErrorAction SilentlyContinue))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name '\CredentialsDelegation' -ErrorAction SilentlyContinue
    }

    if( -not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if(-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -ErrorAction SilentlyContinue))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -value "wsman/$env:COMPUTERNAME" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -value "wsman/localhost" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -value "wsman/*.$DomainName" -PropertyType string -ErrorAction SilentlyContinue
    }

    Write-Verbose "DONE:Setting up CredSSP for NTLM"
}

