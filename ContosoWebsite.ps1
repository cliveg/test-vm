Configuration ContosoWebsite
{
  param ($MachineName)

  Node ($MachineName)
  {
     WindowsFeature WebServerManagementConsole
    {
        Name = "Web-Mgmt-Console"
        Ensure = "Present"
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