##########################################################################################
# Automated Crowdstrike Falcon Sensor deployment script.                                 #
# Put the WindowsSensor.exe in the C:\ drive. Will write an output log to your C:\ drive.#
# Gather a list of your servers in a text document, each separated by a new line.        #
##########################################################################################

$servers_loc = Read-Host -Prompt "Absolute server list location: "
$servers = Get-Content $servers_loc
[System.Collections.ArrayList]$servers = $servers
$global:servers_final = @()
$log = "C:\Crowdstrike_Deploy_Log.txt"

function resolve_hosts {
    foreach ($server in $servers) {
        try {
            Resolve-DnsName -name $server -ErrorAction "Stop"
            $global:servers_final += $server
        }
        catch {
            Write-Output "[-] $($server) ==> Not resolving. Verify host is actually up."
            "[-] $($server) ==> Not resolving. Verify host is actually up." | Out-File $log -Append
            continue
        }
    }
}

function establish_session {
    $s = New-PSSession -ComputerName $args[0]
    return $s
}

function verify_os {
    $os = Invoke-Command -Session $args[0] -ScriptBlock { (Get-WMIObject win32_operatingsystem).name }
    if ($os -notlike "*Windows Server 2012*") {
        Remove-PSSession $args[0]
        Write-Output "[-] $($server) ==> Not Windows Server 2012."
        "[-] $($server) ==> Not Windows Server 2012." | Out-File $log -Append
        continue
    }
}

function verified_sep_removed {
    try {
        $sep = Invoke-Command -Session $args[0] -ScriptBlock { Get-Service -Name "SepMasterService" } -ErrorAction "Stop"
        Remove-PSSession $args[0]
        Write-Output "[-] $($server) ==> SEP still installed. Please remove SEP before installing Crowdstrike Falcon."
        "[-] $($server) ==> SEP still installed. Please remove SEP before installing Crowdstrike Falcon." | Out-File $log -Append
        continue
    }
    catch {
        return
    }
}

function verify_cs_not_installed {
    try {
        $cs = Invoke-Command -Session $args[0] -ScriptBLock { Get-Service -Name "csagent" } -ErrorAction "Stop"
        Remove-PSSession $args[0]
        Write-Output "[+] $($server) ==> CS Falcon already installed"
        "[+] $($server) ==> CS Falcon already installed" | Out-File $log -Append
        continue
    }
    catch {
        return
    }
}

function execution {
    try {
        New-PSDrive -Name $server -PSProvider "Filesystem" -Root "\\$($server)\C$"
        Write-Output "[!] $($server) ==> Creating directory structure..."
        New-Item "$($server):\Crowdstrike" -Type d
        Write-Output "[!] $($server) ==> Copying Falcon sensor..."
        Copy-Item -Path "C:\WindowsSensor.exe" -Destination "$($server):\Crowdstrike\"
        Remove-PSDrive -Name $server 
        Write-Output "[+] $($server) ==> Falcon ready to fly!"
        Start-Sleep -s 2

        Write-Output "[!] $($server) ==> Beginning Crowdstrike Falcon installation... this may take awhile."
        Invoke-Command -Session $args[0] -ScriptBlock { cmd.exe /c "C:\Crowdstrike\WindowsSensor.exe /install /quiet" | Out-Null } -ErrorAction "Stop"
    }
    catch { 
        Write-Output "[-] $($server) ==> Something went wrong during installation. Please try manually."
        "[-] $($server) ==> Something went wrong during installation. Plese try manually." | Out-File $log -Append
        continue
    }
}

function verify {
    try {
        Invoke-Command -Session $session -ScriptBlock { $r = Get-Service csagent } -ErrorAction "Stop"
        Write-Output "[+] $($server) ==> Falcon installed and verified successfully!"
        "[+] $($server) ==> Falcon installed and verified successfully!" | Out-File $log -Append
    }
    catch {
        Write-Output "[-] $($server) Cannot verify 'csagent' service is running. Please verify manually."
        "[-] $($server) Cannot verify 'csagent' service is running. Please verify manually." | Out-File $log -Append
        continue
    }
}

function main {
    resolve_hosts

    foreach ($server in $servers_final) {
        Write-Output "\/###### Beginning CROWDSTRIKE FALCON SENSOR install process on $($server) ######\/"
        "\/###### Beginning CROWDSTRIKE FALCON SENSOR install process on $($server) ######\/" | Out-File $log -Append
        Start-Sleep -s 2
        $session = establish_session $server
        verify_os $session
        verified_sep_removed $session
        verify_cs_not_installed $session
        execution $session
        verify $session
        Remove-PSSession $session
    }
}

main