function Get-SESUMServerInfo {
<#
.SYNOPSIS
Recupera informações sobre o servidor PDC (Primary Domain Controller) de um cartório eleitoral.

.DESCRIPTION
O comando Get-SESUMServerInfo recupera informações básicas a 
respeito de um servidor PDC (Primary Domain Controller) de um
Cartório Eleitoral .

.PARAMETER ZonaEleitoral
Recupera inforamção do servidor da ZonaEleitoral especificada

.PARAMETER fonte
Local de aramazenamento da fonte de informações dos servidores.
O padrão é o arquivo servidores.csv encontrado na pasta do módulo.
#>
    [CmdletBinding()]
    param (
       [Parameter(HelpMessage="Entre com uma zona eleitoral com 3 dígitos")]    
        [ValidateScript({Test-Zona -Zona $_})] 
        
        [string[]]$ZonaEleitoral,

        [string]$fonte = "$PSScriptRoot\servidores.csv",
        
        [switch]$All
    )
    BEGIN {
        $csv_params = @{'Path' = $fonte
                        'Delimiter' = ';'
                        'Encoding' = 'Default'
        }
        $servers_info = Import-CSV @csv_params
    }
    PROCESS {
        if ($All){
            Write-Verbose "Todos os servidores"
            $serverInfo = $servers_info ;
            foreach($server in $serverInfo){
                Write-Verbose "Realizando o output"
                $props = @{'Nome' = $server.COMPUTADOR
                            'IP' = $server.IP
                            'Sede' = $server.SEDE
                            'Zona Eleitoral' = $server.ZE_1
                        }
                $obj = New-Object -TypeName psobject -Property $props
                $obj = $obj | Add-Credential
                Write-Output $obj
            }
        }
        else {            
            foreach($zona in $ZonaEleitoral){
                Write-Verbose "Consultando dados da Zona $zona"
                $serverInfo = $servers_info | 
                              Where-Object {($_.ZE_1 -eq $zona) -or ($_.ZE_2 -eq $zona) -or ($_.ZE_3 -eq $zona)}   
                 Write-Verbose 'Realizando o output'
                 $props = @{'Nome' = $serverInfo.COMPUTADOR
                            'IP' = $serverInfo.IP                       
                            'Sede' = $serverInfo.SEDE
                            'Zona Eleitoral' = $zona}
                $obj = New-Object -TypeName psobject -Property $props
                $obj = $obj | Add-Credential
                Write-Output $obj
            }
        }                
       
    }
    END {}
    
}

function Test-Zona {
    param(
        [string]$Zona    
    )
    $zonas2 = @()
    $servidores = Import-Csv -Path "$PSScriptRoot\servidores.csv" -Delimiter ';' -Encoding Default
    foreach ($servidor in $servidores) {
         $zonas2 += $servidor.ZE_1
         if ($servidor.ZE_2 -ne ''){
             $zonas2  += $servidor.ZE_2
         }
         if ($servidor.ZE_3 -ne ''){
             $zonas2 += $servidor.ZE_3
         }                
     } 
     if ($zonas2 -contains $Zona)
     {         
        $true
     }
     else {
        throw 'Zona Eleitoral nao válida. Por favor tente novamente'
     }
     
}

function Add-Credential {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [object]$Servidor
    )
    $numDominio = $($Servidor.Nome).Substring(3, 3)   
   if ($($Servidor.Nome).startswith("Z")) {
        $dominio = "ZNE-MA" + $numDominio + ".JUS.BR\"
    }
    else {
        $dominio = "CAE-MA" + $numDominio + ".JUS.BR\"
    }

    $usuario = $dominio + "remoto"
    $secpasswd = ConvertTo-SecureString "GOLDConecta20" -AsPlainText -Force
    $mycreds = New-Object System.Management.Automation.PSCredential($usuario, $secpasswd)
    $Servidor | Add-Member -NotePropertyName Credencial -NotePropertyValue $mycreds
    Write-Output $Servidor
}

function Test-SESUMPowershellRemote {
    [cmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [object[]]$InputObject
    )
    BEGIN{}
    PROCESS{
        foreach($server in $InputObject){
            $params = @{'ComputerName' = $server.IP
                        'ErrorAction' = 'SilentlyContinue'}
            $wsman = Test-WSMan @params
            if ($wsman){
                $server | Add-Member -MemberType NoteProperty -Name RemoteStatus -Value 'SUCESSS'              
            } else {
                $server | Add-Member -MemberType NoteProperty -Name RemoteStatus -Value 'FAILURE'  
            }
            Write-Output $server
        }
    }
}

function Get-SESUMUsuariosZona{
    [cmdletBinding()]
    param(
        [Parameter(HelpMessage="Entre com uma zona eleitoral com 3 dígitos")]    
        [ValidateScript({Test-Zona -Zona $_})] 
        [string]$ZonaEleitoral
    )
    BEGIN {
        $server = Get-SESUMServerInfo -ZonaEleitoral $ZonaEleitoral
    }
    PROCESS{
        $params = @{'ScriptBlock' = {Get-ADUser -Filter * -Properties * | Select-Object -Property GivenName,DisplayName,whenCreated,LockedOut}
                    'ComputerName' = $server.IP
                    'Credential' = $server.Credencial}

            $users = Invoke-Command @params

            Write-Output $users
        

        }
    
    END{}

}