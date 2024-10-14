#This script is written to parse the Caldera event-logs report type in JSON format.
#It compares two result files to get the count of successful abilities and determines abilities with different status.
function GetResultsFromFolder { 
    param
    (
        [string] $folderPath
    )

    $abilities = @{}

    $files = Get-ChildItem $folderPath

    foreach ($file in $files) {

        $jsonResults = Get-Content $file.FullName -Raw -Encoding "UTF8" | ConvertFrom-Json

        foreach ($element in $jsonResults) {
            $ability = @{}
            $ability.Add("Name", $element.ability_metadata.ability_name)
            $ability.Add("Command", $element.command)
            $ability.Add("Result", $element.status)
            $ability.Add("stdout", $element.output.stdout)
            $ability.Add("stderr", $element.output.stderr)
            $ability.Add("exit_code", $element.output.exit_code)     
            $ability.Add("agent", $element.agent_metadata.paw)
            $ability.Add("host", $element.agent_metadata.host)
            
    
            $abilities.Add($element.ability_metadata.ability_id, $ability)
        }
    }

    return $abilities
}

function CompareResultsCount {
    #Assumptions: 
    # - Both resultsets contain the same abilities
    # - Abilities contain no cleanup command
    param (
        [hashtable] $results1,
        [hashtable] $results2
    )

    $counter1 = 0
    $counter2 = 0

    $systemname1 = $results1[($results1.Keys)][0].host
    $systemname2 = $results2[($results1.Keys)][0].host


    foreach ($ability in $results1.Keys) {
        if ([int]$results1[$ability].Result -eq 0) {
            $counter1++
        }   
    }

    foreach ($ability in $results2.Keys) {
        if ([int]$results2[$ability].Result -eq 0) {
            $counter2++
        }   
    }

    Write-Output "Successful attacks on $systemname1 : $counter1"
    Write-Output "Successful attacks on $systemname2 : $counter2"

}

function CompareResultsPerAbility {
    #Assumptions: 
    # - Both resultsets contain the same abilities
    # - The same ability is only executed once per Machine
    # - Abilities contain no cleanup command
    param (
        [hashtable] $results1,
        [hashtable] $results2,
        [bool] $system1,
        [bool] $system2
    )

    $differentResults = New-Object System.Collections.Generic.List[System.Object]
    $successful1AndNot2 = New-Object System.Collections.Generic.List[System.Object]
    $successful2AndNot1 = New-Object System.Collections.Generic.List[System.Object]

    foreach ($id in $results1.Keys) {
        $ability1 = $results1[$id]
        $ability2 = $results2[$id] 

        if ([int]$ability1.Result -ne [int]$ability2.Result) {
            Write-Output "Ability: $($ability1.Name) has different Results. $($ability1.host) : $($ability1.Result) ; $($ability2.host) : $($ability2.Result)"
            $differentResults.Add($ability1.Name)

            if ((([int]$ability1.Result -eq 0) -and ([int]$ability2.Result -eq 1)) -or (([int]$ability1.Result -eq 0) -and ([int]$ability2.Result -eq 124))) {
                $successful1AndNot2.Add($ability1.Name)
            }
            if ((([int]$ability2.Result -eq 0) -and ([int]$ability1.Result -eq 1)) -or (([int]$ability2.Result -eq 0) -and ([int]$ability1.Result -eq 124))) {
                $successful2AndNot1.Add($ability2.Name)
            }
        }
    }
    
    $systemname1 = $results1[($results1.Keys)][0].host
    $systemname2 = $results2[($results2.Keys)][0].host


    if ($system1) {
        Write-Output "Successful Abilities on $systemname1 and not successful on $systemname2 : $successful1AndNot2"
        Write-Output "NOT Successful Abilities on $systemname1 but successful on $systemname2 : $successful2AndNot1"
    }

    if ($system2) {
        Write-Output "Successful Abilities on $systemname2 and not successful on $systemname1 : $successful2AndNot1"
        Write-Output "NOT Successful Abilities on $systemname2 but successful on $systemname1 : $successful1AndNot2"
    }
}


$results1 = GetResultsFromFolder ""
$results2 = GetResultsFromFolder ""

#NOTE: Caldera cleanup commands will also be in the result event-logs but can not be distinguished from the related ability, because cleanup command in the event-log has the same ability name and id.
# -> So cleanup commands will affect the count and ability comparison and therefore have to be deactivated.
CompareResultsCount $results1 $results2
CompareResultsPerAbility $results1 $results2 $true $true
