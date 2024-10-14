#This script automates the iterative method to set single registry settings and trigger Caldera to attack the target system.
#It compares the results of the Caldera runs and determines the impact of single settings or combinations of settings on the security level.

param(
    [Parameter(Mandatory)]
    [String] $RunMode
)

Import-Module $PSScriptRoot\caldera_api.psm1 -Force
Import-Module $PSScriptRoot\Combination_adjusted.psm1 -Force

$script:TargetSystemIP = ""
$script:AttackerSystemIP = ""
#This is for SSH connection
$script:AdminUserNameTargetSystem = ""

#Assumption: Cladera Agent Paw and Group must be equal
#Key: Agent Group, Value: Adversary Profile
$script:AttackPlans = @{"Win11-23H2-User" = "Windows Hardening Test - User Scope"; 
    "Win11-23H2-AdminUnelevated" = "Windows Hardening Test - Unelevated Scope"; 
    "Win11-23H2-System" = "Windows Hardening Test - System Scope";
    "Win11-Attack-AdminElevated" = "Windows Hardening Test - Elevated Scope - Remote";
    "Win11-23H2-AdminElevated" = "Windows Hardening Test - Elevated Scope - Local"
}

#Specify accounts with Hostname or Netbios prefix e.g. PCName\Admin; LAB\Alice
$script:UsersWhereToChangeSettings = @("", "")
$script:SIDsWhereToChangeSettings = $null

#Use short naming convention in settings file! e.g. HKLM:\...
$script:SettingsFile = ""

#Do not adjust the following variables
$script:RegSettingsWithStartValues = $null
$global:RegistryTypes = @{"REG_BINARY" = "Binary"; "REG_DWORD" = "DWord"; "REG_EXPAND_SZ" = "ExpandString"; "REG_MULTI_SZ" = "MultiString";
    "REG_QWORD" = "QWord"; "REG_SZ" = "String"
}
$script:allRunResults = @{}
$script:RunCounter = 0


function StartEmulation {
    param (
        [Parameter(Mandatory)]
        [array] $runMode
    )
    if ($runMode -eq "Isolated") {
        IsolatedMode
    }

    if ($runMode -eq "Additive") {
        AdditiveMode
    }
}

#Compare always just one setting with starting config
function IsolatedMode {
    $originalStateResults = NewRun
    $script:allRunResults["Run $RunCounter"] = @{"Results" = $originalStateResults }

    foreach ($setting in $script:RegSettingsWithStartValues) {
        $script:RunCounter ++
        Write-Host "Starting new run for setting: $($setting.KeyName)\$($setting.ValueName)"
        ChangeUserOrMachineSetting $setting
        RebootAndWait
        $singleRunResults = NewRun
        $script:allRunResults["Run $RunCounter"] = @{"ChangedSetting" = $setting; "Results" = $singleRunResults }

        $equal = CompareTwoRunResults 0 $RunCounter
        if ($equal[0]) {
            Write-Host "No impact from setting change"
            $script:allRunResults["Run $RunCounter"].Add("SingleImpact" , $false)
            Write-Host "Revert change"
            ChangeUserOrMachineSetting $setting -revert $true
            #RebootAndWait
        }
        else {
            Write-Host "Setting change lead to impact!"
            $script:allRunResults["Run $RunCounter"].Add("SingleImpact" , $true)
            $abilitiesPerRun = CompareTwoRunResultsPerAbility 0 $RunCounter
            Write-Host "Successful Abilities on Run $RunCounter and not successful on Run 0 :"
            $abilitiesPerRun[0] | Out-String
            Write-Host "NOT Successful Abilities on Run $RunCounter but successful on Run 0 :"
            $abilitiesPerRun[1] | Out-String
            $script:allRunResults["Run $RunCounter"].Add("NowSuccessfulAndNotOnBaseSystem" , $abilitiesPerRun[0])
            $script:allRunResults["Run $RunCounter"].Add("NotSuccessfulOnBaseSystemButNow" , $abilitiesPerRun[1])
            Write-Host "Revert change"
            ChangeUserOrMachineSetting $setting -revert $true
            #RebootAndWait
        }
    }
    Write-Host "End reached. Checked all specified settings."
}

function AdditiveMode {
    #First run for getting results for starting point
    Write-Host "First run to get base state."
    $originalStateResults = NewRun
    $script:allRunResults["Run $RunCounter"] = @{"Results" = $originalStateResults }
    $setSettings = @()
    $runWithLastChange = 0

    foreach ($setting in $script:RegSettingsWithStartValues) {
        $script:RunCounter ++
        Write-Host "Starting new run for setting: $($setting.KeyName)\$($setting.ValueName)"
        ChangeUserOrMachineSetting $setting
        RebootAndWait
        $singleRunResults = NewRun
        $script:allRunResults["Run $RunCounter"] = @{"ChangedSetting" = $setting; "AllSettingsUntilNow" = $setSettings; "Results" = $singleRunResults }
        $setSettings += $setting
 
        $equal = CompareTwoRunResults $runWithLastChange $RunCounter
        if ($equal[0]) {
            Write-Host "No impact from setting change related to last run."
        }
        else {
            Write-Host "Setting change lead to impact compared to last run!"
            $oldLastChangeCounter = $runWithLastChange
            $runWithLastChange = $RunCounter             
                
            $abilitiesDifferentToStart = CompareTwoRunResultsPerAbility 0 $RunCounter

            if ($oldLastChangeCounter -gt 0) {
                #check equality to start state
                $equalToStart = CompareTwoRunResults 0 $RunCounter
                #if count and ability exactly same
                if (($equalToStart[0]) -and (!$abilitiesDifferentToStart[2])) {
                    Write-Host "No difference to start state!"
                    $script:allRunResults["Run $RunCounter"]["DifferenceToStartState"] = $false
                    Write-Host "Combination of following settings does not have any effects:"
                    $setSettings | Out-String
                    continue
                }

                if (($equalToStart[0]) -and ($abilitiesDifferentToStart[2])) {
                    Write-Host "Same count but difference in abilities to start state!"
                    $script:allRunResults["Run $RunCounter"]["DifferentAbilitiesToStartState"] = $abilitiesDifferentToStart[2]
                    Write-Host "Successful Abilities on Run $RunCounter and not successful on Run 0 :"
                    $abilitiesDifferentToStart[0] | Out-String
                    Write-Host "NOT Successful Abilities on Run $RunCounter but successful on Run 0 :"
                    $abilitiesDifferentToStart[1] | Out-String
                    Write-Host "A combination of the following settings lead to this effect:"
                    $setSettings | Out-String
                    Write-Host "No further checking which combination..."
                    continue
                }
            }

            $script:allRunResults["Run $RunCounter"]["DifferentAbilitiesToStartState"] = $abilitiesDifferentToStart[2]
            Write-Host "Successful Abilities on Run $RunCounter and not successful on Run 0 :"
            $abilitiesDifferentToStart[0] | Out-String
            Write-Host "NOT Successful Abilities on Run $RunCounter but successful on Run 0 :"
            $abilitiesDifferentToStart[1] | Out-String

            if ($RunCounter -eq 1) {
                $Run1VsOriginal = $equal[2] - $equal[1]
                $script:allRunResults["Run $RunCounter"].Add("SingleImpactToStartState" , $true)
                $script:allRunResults["Run $RunCounter"]["LeadToImpactOnlyInCombinationWithOtherSettings"] = $false
                $script:allRunResults["Run $RunCounter"].Add("SingleImpactCount", $Run1VsOriginal)
                $setSettings[-1] | Add-Member -NotePropertyName SingleImpactCount -NotePropertyValue $Run1VsOriginal
                Write-Host "Single setting was responsible for impact!"
            }

            #First Run counts as single change and must not be reverted
            if ($RunCounter -gt 1) {
                Write-Host "Several changes were made. Revert changes and testing single setting to test if the combination of the settings lead to impact."
                RevertAllSettings $setSettings
                #Single setting only
                ChangeUserOrMachineSetting $setting
                RebootAndWait
                $originalRunCounter = $RunCounter
                $tempNumber = $RunCounter + 0.1
                $script:RunCounter = $tempNumber
                $newRunResults = NewRun
                $script:RunCounter = $originalRunCounter
                
                $equalNew = CompareRunResultsObjects $originalStateResults $newRunResults 0 $tempNumber
                $newVsOriginal = $equalNew[2] - $equalNew[1]
                $oldRunVsNewRun = $equal[2] - $equal[1]
                
                if ($equalNew[0]) {
                    $script:allRunResults["Run $RunCounter"].Add("SingleImpactToStartState" , $false)
                    $script:allRunResults["Run $RunCounter"]["LeadToImpactInCombinationWithOtherSettings"] = $true
                    Write-Host "No impact from single setting. A combination of settings were responsible for changes in results."
                    Write-Host "All settings set when impact recognized:"
                    $setSettings | Out-String
                    #Extension find out responsible combination
                    Write-Host "Start to find out responsible combination."
                    $lastSetting = $script:allRunResults["Run $RunCounter"]["ChangedSetting"]
                    $allSettingsBefore = $script:allRunResults["Run $RunCounter"]["AllSettingsUntilNow"]
                    TestCombinations $lastSetting $allSettingsBefore $oldRunVsNewRun
                    #Extension End
                    Write-Host "Testing combinations finished."
                    Write-Host  "Go to last Additive State and continue."
                    ReturnToAdditiveState $setSettings
                    RebootAndWait
                    continue
                }

                #Single Setting lead to same count impact
                if ($newVsOriginal -eq $oldRunVsNewRun) {
                    $script:allRunResults["Run $RunCounter"].Add("SingleImpactToStartState" , $true)
                    $script:allRunResults["Run $RunCounter"]["LeadToImpactOnlyInCombinationWithOtherSettings"] = $false
                    $script:allRunResults["Run $RunCounter"].Add("SingleImpactCount", $newVsOriginal)
                    $setSettings[-1] | Add-Member -NotePropertyName SingleImpactCount -NotePropertyValue $newVsOriginal
                    Write-Host "Single setting was responsible for impact!"
                    Write-Host  "Go to Last Additive State and continue."
                    ReturnToAdditiveState $setSettings
                    RebootAndWait
                }
                else {
                    #Lead to impact, but not full impact
                    $script:allRunResults["Run $RunCounter"].Add("PartiallyImpactToStartState" , $true)
                    $script:allRunResults["Run $RunCounter"]["LeadToImpactInCombinationWithOtherSettings"] = $true
                    $script:allRunResults["Run $RunCounter"].Add("SingleImpactCount", $newVsOriginal)
                    $setSettings[-1] | Add-Member -NotePropertyName SingleImpactCount -NotePropertyValue $newVsOriginal
                    Write-Host "Single setting had partially impact!"
                    #Extension find out responsible combination
                    Write-Host "Start to find out responsible combination."
                    $lastSetting = $script:allRunResults["Run $RunCounter"]["ChangedSetting"]
                    $allSettingsBefore = $script:allRunResults["Run $RunCounter"]["AllSettingsUntilNow"]
                    TestCombinations $lastSetting $allSettingsBefore $oldRunVsNewRun
                    #Extension End
                    Write-Host "Testing combinations finished."
                    Write-Host  "Go to Last Additive State and continue."
                    ReturnToAdditiveState $setSettings
                    RebootAndWait
                }
            }
        }
    }
    Write-Host "End reached. Checked all specified settings."
}

function ReturnToAdditiveState {
    param (
        [array] $setSettings
    )
    foreach ($setting in $setSettings) {
        ChangeUserOrMachineSetting $setting
    }
    
}

function RevertAllSettings {
    param (
        [array] $setSettings
    )
    foreach ($setting in $setSettings) {
        ChangeUserOrMachineSetting $setting -revert $true
    }
}

function ChangeUserOrMachineSetting {
    param (
        [PSCustomObject] $registrySetting,
        [bool] $revert
    )

    #To simplify set and revert user setting for all specified users
    if ($registrySetting.KeyName -match "HKCU:") {
        $orginalKeyName = $registrySetting.KeyName
        foreach ($sid in $script:SIDsWhereToChangeSettings) {
            $registrySetting.KeyName = ($orginalKeyName).Replace("HKCU:", "Registry::HKEY_USERS\$sid")
            ChangeSetting $registrySetting $revert
        }     
    }
    else {
        #This is a machine setting
        ChangeSetting $registrySetting $revert
    }
} 

function ChangeSetting {
    param (
        [PSCustomObject] $registrySetting,
        [bool] $revert
    )
    $registryPath = $registrySetting.KeyName
    $registryValueName = $registrySetting.ValueName
    $registryValueData = $registrySetting.ValueData
    $registryType = $RegistryTypes[$registrySetting.ValueType]


    if (!$revert) {
        $session = New-PSSession -HostName $TargetSystemIP -UserName $AdminUserNameTargetSystem
        Invoke-Command -Session $session -ScriptBlock {
            If (-NOT (Test-Path $Using:registryPath)) {
                New-Item -Path $Using:registryPath -Force | Out-Null
            }  
            # Set the value
            Set-ItemProperty -Path $Using:registryPath -Name $Using:registryValueName -Value $Using:registryValueData -Type  $Using:registryType -Force    
        }
    }

    if ($revert) {
        $registryOriginalValue = $registrySetting.OriginalValue
        $session = New-PSSession -HostName $TargetSystemIP -UserName $AdminUserNameTargetSystem

        if (!$registrySetting.Existed) {
            Invoke-Command -Session $session -ScriptBlock {
                Remove-ItemProperty -Path $Using:registryPath -Name $Using:registryValueName
            }
        }
        if ($registrySetting.Existed) {
            Invoke-Command -Session $session -ScriptBlock {
                Set-ItemProperty -Path $Using:registryPath -Name $Using:registryValueName -Value $Using:registryOriginalValue -Type  $Using:registryType -Force
            }  
        }
    }

    Remove-PSSession $session
}

function RebootAndWait {
    $session = New-PSSession -HostName $TargetSystemIP -UserName $AdminUserNameTargetSystem
    Invoke-Command -Session $session -ScriptBlock {
        shutdown /f /r /t 0
    }
    $ssh = $null
    Start-Sleep 20

    While (-not $ssh) {
        Try  
        {
            $ssh = New-PSSession -HostName $TargetSystemIP -UserName $AdminUserNameTargetSystem -ea Stop -WarningAction SilentlyContinue
        }
        Catch
        { 
            Write-Host 'Waiting for reboot...' 
        }
        Start-Sleep 10
    }
    Remove-PSSession $ssh
    #This is needed to wait for services with delayed start.
    Start-Sleep 30 
}

function NewRun {
    $runResults = New-Object -TypeName System.Collections.ArrayList
    foreach ($attackPlan in $AttackPlans.Keys) {

        $adversaryId = ((GetAdversaryProfileByName ($AttackPlans[$attackPlan]))[0]).adversary_id
        #Source id means the fact source, in this case 'basic'
        $operationName = $AttackPlans[$attackPlan] + ": Run " + $script:RunCounter
        $operationBody = '{{"name": "{0}" ,"group": "{1}","adversary":{{"adversary_id": "{2}" }},
        "auto_close":true,"state":"running","autonomous":1,"planner":{{"id":"aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"}},"source":{{"id":"ed32b9c3-9593-4c33-b0db-e2007315096b"}},
        "use_learning_parsers":false,"obfuscator":"plain-text","jitter":"2/8","visibility":"51"}}' -f $operationName, $attackPlan, $adversaryId

        $operation = NewOperation -body $operationBody

        $operationId = $operation.id
        $operationName = $operation.name
        $finished = $false
        Write-Host "Wait for operation to finish."
        while (-Not $finished) {
            $operation = GetOperation $operationId
            if ($operation.state -eq "finished") {
                $finished = $true
                break
            }
            Start-Sleep 30
        }
        Write-Host "Operation: $operationName has finished"
        $results = GetOperationLog -operationId $operationId
        $abilities = ParseResultReturnIntoObjects $results
        foreach ($ability in $abilities) {
            $runResults.Add($ability) | Out-Null
        }
    }
    return $runResults
} 


function CompareTwoRunResults {
    param
    (
        [int] $baseRun,
        [int] $newRun
    )

    $baseRunAbilities = $script:allRunResults["Run $baseRun"]["Results"]
    $newRunAbilities = $script:allRunResults["Run $newRun"]["Results"]
    $baseRunCount = 0
    $newRunCount = 0

    foreach ($ability in $baseRunAbilities) {
        if ([int]$ability.Result -eq 0) {
            $baseRunCount++
        }   
    }

    foreach ($ability in $newRunAbilities) {
        if ([int]$ability.Result -eq 0) {
            $newRunCount++
        }
    }

    if ($baseRunCount -ne $newRunCount) {
        Write-Host "Run $baseRun had $baseRunCount successful attacks; Run $newRun has $newRunCount successful attacks."
        return @($false, $baseRunCount, $newRunCount)
    }

    return @($true, $baseRunCount, $newRunCount)

}

function CompareRunResultsObjects {
    param
    (
        [array] $baseRun,
        [array] $newRun,
        [double] $baseNumber,
        [double] $runNumber 
    )

    $baseRunCount = 0
    $newRunCount = 0

    foreach ($ability in $baseRun) {
        if ([int]$ability.Result -eq 0) {
            $baseRunCount++
        }   
    }

    foreach ($ability in $newRun) {
        if ([int]$ability.Result -eq 0) {
            $newRunCount++
        }
    }

    if ($baseRunCount -ne $newRunCount) {
        Write-Host "Run $baseNumber had $baseRunCount successful attacks; Run $runNumber has $newRunCount successful attacks"
        return @($false, $baseRunCount, $newRunCount)
    }
    return @($true, $baseRunCount, $newRunCount)

}


function CompareTwoRunResultsPerAbility {
    #Assumptions: 
    # - Both resultsets contain the same abilities
    # - The same ability is only executed once per machine
    param (
        [int] $baseRun,
        [int] $newRun
    )

    $baseRunAbilities = $script:allRunResults["Run $baseRun"]["Results"]
    $newRunAbilities = $script:allRunResults["Run $newRun"]["Results"]

    $differentResults = New-Object -TypeName System.Collections.ArrayList
    $successful1AndNot2 = New-Object -TypeName System.Collections.ArrayList
    $successful2AndNot1 = New-Object -TypeName System.Collections.ArrayList


    For ($i = 1; $i -le ($baseRunAbilities.Count); $i++) {
        $ability1 = $baseRunAbilities[$i - 1]
        $ability2 = $newRunAbilities[$i - 1]

        if ([int]$ability1.Result -ne [int]$ability2.Result) {
            Write-Host "Ability: $($ability1.Name) has different Results. Run $baseRun : $($ability1.Result) ; Run $newRun : $($ability2.Result)"
            $differentResults.Add($ability1.Name) | Out-Null  

            if ((([int]$ability1.Result -eq 0) -and ([int]$ability2.Result -eq 1)) -or (([int]$ability1.Result -eq 0) -and ([int]$ability2.Result -eq 124))) {
                $successful1AndNot2.Add($ability1.Name) | Out-Null 
            }
            if ((([int]$ability2.Result -eq 0) -and ([int]$ability1.Result -eq 1)) -or (([int]$ability2.Result -eq 0) -and ([int]$ability1.Result -eq 124))) {
                $successful2AndNot1.Add($ability2.Name) | Out-Null 
            }
        }
    }
 
    return @($successful2AndNot1, $successful1AndNot2, $differentResults)
}


function ParseResultReturnIntoObjects {

    param
    (
        [array] $results
    )

    $abs = New-Object System.Collections.ArrayList
    foreach ($element in $results) {

        $ability = New-Object -TypeName PSCustomObject
        $ability | Add-Member -MemberType NoteProperty -Name "Name" -Value $element.ability_metadata.ability_name
        $ability | Add-Member -MemberType NoteProperty -Name "Command" -Value $element.command
        $ability | Add-Member -MemberType NoteProperty -Name "Result" -Value $element.status
        $ability | Add-Member -MemberType NoteProperty -Name "stdout" -Value $element.output.stdout
        $ability | Add-Member -MemberType NoteProperty -Name "stderr" -Value $element.output.stderr
        $ability | Add-Member -MemberType NoteProperty -Name "exit_code" -Value $element.output.exit_code
        $ability | Add-Member -MemberType NoteProperty -Name "agent" -Value $element.agent_metadata.paw
        $ability | Add-Member -MemberType NoteProperty -Name "host" -Value $element.agent_metadata.host
        
        $abs.Add($ability) | Out-Null 

    }
    return , $abs
}

function GetStartValues {
    param (
        [array]$regSettings
    )
    $session = New-PSSession -HostName $TargetSystemIP -UserName $AdminUserNameTargetSystem

    foreach ($setting in $regSettings) {
        $commandResult = Invoke-Command -Session $session -ScriptBlock {
            $valueObject = Get-ItemProperty -Path $Using:setting.KeyName -Name $Using:setting.ValueName -ErrorAction SilentlyContinue
            Write-Output $valueObject
        }

        if (!$commandResult) {
            $setting | Add-Member -NotePropertyName Existed -NotePropertyValue $false
        }

        if ($commandResult) {
            $setting | Add-Member -NotePropertyName Existed -NotePropertyValue $true
            $value = $commandResult.($setting.ValueName)
            $setting | Add-Member -NotePropertyName OriginalValue -NotePropertyValue $value
        }
    }
    
    Remove-PSSession $session
    return $regSettings
}

function GetUsersHKUSID {
    param (
        [array]$userNames 
    )
    #When Domain and Local account have same name, following hive names are possible:
    #Administrator 
    #Administrator.ComputerName
    #Administrator.Domain (NETBIOS Name)

    $session = New-PSSession -HostName $TargetSystemIP -UserName $AdminUserNameTargetSystem
    $commandResult = Invoke-Command -Session $session -ScriptBlock {
        $computerName = $Env:ComputerName
        #$netbiosName = $env:userdomain
        $netbiosName = (nbtstat -n | ?{$_ -match '\<00\>  GROUP'}).Split()[4]
        #$fqdn = $env:userdnsdomain

        $PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
 
        $allProfiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object { $_.PSChildName -match $PatternSID } |
        select  @{name = "SID"; expression = { $_.PSChildName } },
        #@{name = "UserHive"; expression = { "$($_.ProfileImagePath)\ntuser.dat" } },
        @{name = "Username"; expression = { $_.ProfileImagePath -replace '^(.*[\\\/])', '' } }

        $userHiveNames = @()

        foreach ($user in $using:userNames) {

            $split = $user.Split("\")
            $foundProfiles = @()

            foreach ($profile in $allProfiles) {

                if ($profile.Username -match $split[1]) {
                    $foundProfiles += $profile
                }
            }

            if ($foundProfiles.Count -eq 2) {
                #Found Local and Domain Account with same name
                $localWithoutPrefix = $null

                if (($foundProfiles[0].Username -match ".$netbiosName") -or ($foundProfiles[1].Username -match ".$netbiosName")) {
                    $localWithoutPrefix = $true
                }
                else {
                    $localWithoutPrefix = $false
                }

                if ($localWithoutPrefix -and ($split[0] -eq $computerName) ) {
                    $userHiveNames += $split[1]
                }

                if ((!$localWithoutPrefix) -and ($split[0] -eq $computerName) ) {
                    $userHiveNames += $split[1] + ".$($split[0])"
                }

                if ((!$localWithoutPrefix) -and ($split[0] -eq $netbiosName) ) {
                    $userHiveNames += $split[1]
                }
                
                if ($localWithoutPrefix -and ($split[0] -eq $netbiosName) ) {
                    $userHiveNames += $split[1] + "." + $split[0]
                }
            }
            else {
                #Just one object with this name found, so just take it
                $userHiveNames += $foundProfiles.Username
            }
        }        

        $SIDs = @()
        foreach ($profile in $allProfiles) {
            if ($profile.Username -in $userHiveNames) {
                $SIDs += $profile.SID                
            }
        }
        Write-Output $SIDs

    }

    $script:SIDsWhereToChangeSettings = $commandResult
    Remove-PSSession $session
    if($script:SIDsWhereToChangeSettings.count -eq 0){
        Write-Host "No User Profiles found!"
        Write-Host "Stopping Script!"
        Exit
    }
}

function TestCombinations {
    param (
        [PSCustomObject] $lastRegistrySetting,
        [array]$allSettingsSetBefore,
        [int] $successfulAttacksDelta
    )

    Write-Host "Starting testing combinations of settings. First revert all settings to create base state."
    RevertAllSettings $setSettings
    RebootAndWait

    #For Groups size 1+1, so last setting combined with all single settings before
    $combinations = New-Object -TypeName System.Collections.ArrayList
    foreach ($setting in $allSettingsSetBefore) {
        $combinations.Add(@($lastRegistrySetting, $setting)) | Out-Null
    }

    Write-Host "Begin with last setting + every single setting before"
    $counterIndex = 0.20
    $foundCombination = CheckGroups $counterIndex $combinations 
    
    if ($foundCombination) {
        return
    }
    
    # Build groups of size $i + lastRegistrySetting till allSettingsSetBefore-1
    For ($i = 2; $i -lt $allSettingsSetBefore.Count; $i++) {
        Write-Host "No results. Increasing group size."
        $doubleString = "0." + $($i + 1) + "0"
        $counterIndex = [double]::Parse($doubleString)
        $combinations = Get-Combination $allSettingsSetBefore $i
        $combinations = AddLastSettingToCombinations $lastRegistrySetting $combinations
        Write-Host "Check groups of size $i + last setting."
        $foundCombination = CheckGroups $counterIndex $combinations
        
        if ($foundCombination) {
            return
        }
    }
    Write-Host "Combination of all set settings is responsible for impact!"
    $allSetSettings = $setSettings | Out-String
    Write-Host $allSetSettings
}

function CheckGroups {
    param (
        [double]$counterIndex,
        $combinationsToCheck
    )

    foreach ($combination in $combinationsToCheck) {
        Write-Host "Apply combination:"
        $combinationToString = $combination | Out-String 
        Write-Host $combinationToString
        foreach ($setting in $combination) {
            ChangeUserOrMachineSetting $setting            
        }
        $counterIndex += 0.01
        RebootAndWait
        $originalRunCounter = $RunCounter
        $tempNumber = $RunCounter + $counterIndex 
        $script:RunCounter = $tempNumber
        $newRunResults = NewRun
        $script:RunCounter = $originalRunCounter
        
        $equalNew = CompareRunResultsObjects $originalStateResults $newRunResults 0 $tempNumber
        #No impact from combination, continue with next
        if ($equalNew[0]) {
            Write-Host "No impact from combination, revert settings and continue with next one."
            RevertAllSettings $combination
            RebootAndWait
            continue
        }
        else {
            #Impact from combination, check for same count impact, we have to add impact counter for every setting with single impact because they have impact on base state
            $singleImpactCount = 0
            foreach($setting in $combination){
                $count = $setting.SingleImpactCount
                $singleImpactCount += $count
            }

            $newVsOriginal = $equalNew[2] - ($equalNew[1] + $singleImpactCount)

            #Combination lead to same count impact
            if ($newVsOriginal -eq $successfulAttacksDelta) {
                Write-Host "Found combination responsible for impact!:"
                $combinationToString = $combination | Out-String 
                Write-Host $combinationToString
                return $true
            }
            Write-Host "Only found combination with partially impact. Revert settings and check next one."
            RevertAllSettings $combination
            RebootAndWait
        }
    }
    return $false    
}

function AddLastSettingToCombinations {
    param (
        [PSCustomObject] $lastRegistrySetting,
        [System.Collections.ArrayList] $combinations
    )

    For ($i = 0; $i -lt $combinations.Count; $i++) {
        $combinations[$i] += $lastRegistrySetting
    }

    return $combinations
}


#If involved systems are pingable
if (-Not ((Test-Connection -TargetName $script:TargetSystemIP, $script:AttackerSystemIP -Quiet) -contains $false)) {
    $hardeningSettings = Import-Csv -Path $script:SettingsFile
    #Assumption Users have same default settings! -> SSH Account decides about HKCU default values!
    $script:RegSettingsWithStartValues = GetStartValues $hardeningSettings
    if ($RegSettingsWithStartValues.KeyName -match "HKCU:") {
        GetUsersHKUSID $script:UsersWhereToChangeSettings
    }
    StartEmulation $RunMode
}
else {
    Write-Host "At least one system not pingable!"
} 
