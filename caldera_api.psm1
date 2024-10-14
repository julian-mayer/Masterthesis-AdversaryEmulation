#This script provides functions to call the Caldera API.

#$script:ExampleOperationBody = '{"name":"Windows11-AdminAttacks","group":"Admin","adversary":{"adversary_id":"939da277-16c1-4b93-9580-4783c471d21e"},"auto_close":true,"state":"running","autonomous":1,"planner":{"id":"aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},"source":{"id":"ed32b9c3-9593-4c33-b0db-e2007315096b"},"use_learning_parsers":false,"obfuscator":"plain-text","jitter":"2/8","visibility":"51"}' 

$script:Params = @{
    KEY            = ""
    "Content-Type" = "application/json"
}

function GetOperation {
    param
    (
        [string] $id
    )
    return Invoke-RestMethod -Uri "http://localhost:8888/api/v2/operations/$id" -Headers $script:Params
}

function GetAllOperations {
    return Invoke-RestMethod -Uri "http://localhost:8888/api/v2/operations" -Headers $script:Params
}

function DeleteOperation {
    param
    (
        [string] $id
    )
    return Invoke-RestMethod -Method Delete -Uri "http://localhost:8888/api/v2/operations/$id" -Headers $script:Params
}

function NewOperation {
    param
    (
        [string] $body
    )
    return Invoke-RestMethod -Method POST -Uri "http://localhost:8888/api/v2/operations" -Headers $script:Params -Body $body  
}

function GetOperationLog {
    param (
        [string] $operationId
    )
    return Invoke-RestMethod -Method POST -Uri "http://localhost:8888/api/v2/operations/$operationId/event-logs" -Headers $script:Params -Body '{ 
        "enable_agent_output": true}'
}

function GetAllAdversaries {
    return Invoke-RestMethod -Uri "http://localhost:8888/api/v2/adversaries" -Headers $script:Params
}

function GetAdversaryProfileByName {
    param (
        [string] $name
    )

    $adversaries = GetAllAdversaries
    $results = New-Object System.Collections.Generic.List[System.Object]
      
    foreach ($adv in $adversaries) {
        if ($adv.name -eq $name) {
            $results.Add($adv)
        }
    } 
    return $results
}
