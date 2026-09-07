# SOC N1 Lab - Analise de falhas de autenticacao no Windows

$LogName = "Security"
$FailedEventID = 4625
$SuccessEventID = 4624

# Regra criada para o laboratorio
$Threshold = 4
$StartTime = (Get-Date).AddMinutes(-5)

# Busca falhas de autenticacao recentes
$FailedEvents = Get-WinEvent -FilterHashtable @{
    LogName   = $LogName
    Id        = $FailedEventID
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$FailedCount = @($FailedEvents).Count

if ($FailedCount -ge $Threshold) {

    Write-Host ""
    Write-Host "ALERTA SOC N1"
    Write-Host "Multiplas falhas de autenticacao detectadas."
    Write-Host "Falhas encontradas: $FailedCount"
    Write-Host "Classificacao: Requer investigacao"
    Write-Host ""

    foreach ($Event in $FailedEvents) {

        $Xml = [xml]$Event.ToXml()

        $IpAddress = ($Xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "IpAddress"}).'#text'

        $LogonType = ($Xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "LogonType"}).'#text'

        $TargetUser = ($Xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "TargetUserName"}).'#text'

        $Status = ($Xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "Status"}).'#text'

        $SubStatus = ($Xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "SubStatus"}).'#text'

        $LogonProcess = ($Xml.Event.EventData.Data |
            Where-Object {$_.Name -eq "LogonProcessName"}).'#text'

        Write-Host "-----------------------------------"
        Write-Host "Horario: $($Event.TimeCreated)"
        Write-Host "Event ID: 4625"
        Write-Host "Usuario: $TargetUser"
        Write-Host "IP de origem: $IpAddress"
        Write-Host "Tipo de logon: $LogonType"
        Write-Host "Processo de logon: $LogonProcess"
        Write-Host "Status: $Status"
        Write-Host "SubStatus: $SubStatus"
    }

    # Procura um login valido depois das falhas
    $LastFailure = $FailedEvents |
        Sort-Object TimeCreated |
        Select-Object -Last 1

    $SuccessEvents = Get-WinEvent -FilterHashtable @{
        LogName   = $LogName
        Id        = $SuccessEventID
        StartTime = $LastFailure.TimeCreated
    } -ErrorAction SilentlyContinue

    $RelevantSuccess = $null

    foreach ($SuccessEvent in $SuccessEvents) {

        $SuccessXml = [xml]$SuccessEvent.ToXml()

        $SuccessLogonType = ($SuccessXml.Event.EventData.Data |
            Where-Object {$_.Name -eq "LogonType"}).'#text'

        # 2 = login local / 7 = desbloqueio
        if ($SuccessLogonType -eq "2" -or $SuccessLogonType -eq "7") {
            $RelevantSuccess = $SuccessEvent
            break
        }
    }

    Write-Host ""
    Write-Host "Correlacao:"

    if ($RelevantSuccess) {
        Write-Host "Logon bem-sucedido encontrado."
        Write-Host "Horario: $($RelevantSuccess.TimeCreated)"
        Write-Host "Tipo de logon: $SuccessLogonType"
    }
    else {
        Write-Host "Nenhum logon bem-sucedido relevante encontrado."
    }

    Write-Host ""
    Write-Host "Resultado: INVESTIGAR"
    Write-Host "O alerta nao confirma um ataque."

}
else {

    Write-Host "Nenhum padrao suspeito detectado."
    Write-Host "Falhas encontradas: $FailedCount"
}
