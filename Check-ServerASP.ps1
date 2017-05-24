Function ConvertFrom-AccessMask {
[cmdletbinding()]
Param (
[Parameter(Position=0,Mandatory,HelpMessage="Enter an AccessMask",
ValueFromPipeline,ValueFromPipelineByPropertyName)]
[ValidateNotNullorEmpty()]
[uint32]$AccessMask,
[switch]$AsString
)

Begin {
    Write-Verbose "Starting $($MyInvocation.Mycommand)"  
} #begin

Process {
    Write-Verbose "Decoding $Accessmask"
    $AccessMaskDecode=@()

    If ($AccessMask -bAnd 1048576) {$AccessMaskDecode+= "Synchronize"}
    If ($AccessMask -bAnd 524288)  {$AccessMaskDecode+= "WriteOwner"}
    If ($AccessMask -bAnd 262144)  {$AccessMaskDecode+= "WriteACL"}
    If ($AccessMask -bAnd 131072)  {$AccessMaskDecode+= "ReadSecurity"}
    If ($AccessMask -bAnd 65536)   {$AccessMaskDecode+= "Delete"}
    If ($AccessMask -bAnd 256)     {$AccessMaskDecode+= "WriteAttrib"}
    If ($AccessMask -bAnd 128)     {$AccessMaskDecode+= "ReadAttrib"}
    If ($AccessMask -bAnd 64)      {$AccessMaskDecode+= "DeleteDir"}
    If ($AccessMask -bAnd 32)      {$AccessMaskDecode+= "Execute"}
    If ($AccessMask -bAnd 16)      {$AccessMaskDecode+= "WriteExtAttrib"}
    If ($AccessMask -bAnd 8)       {$AccessMaskDecode+= "ReadExtAttrib"}
    If ($AccessMask -bAnd 4)       {$AccessMaskDecode+= "Append"}
    If ($AccessMask -bAnd 2)       {$AccessMaskDecode+= "Write"}
    If ($AccessMask -bAnd 1)       {$AccessMaskDecode+= "Read"}

    If ($AsString) {
        #join the result as a comma separated string
        Write-Verbose "Writing result as a string"
        $AccessMaskDecode -join ","
    }
    else {
        #write the result to the pipeline
        Write-Verbose "Writing result as an array"
        $AccessMaskDecode
    }

} #process

End {
    Write-Verbose "Ending $($MyInvocation.Mycommand)"
} #end

} #close Get-AccessMask



function Check-NameClienteASP ($nom_cliente, $dom_cliente)
{
    if ($dom_cliente -notmatch "^\.\S*"){
        $dom_cliente = ".$dom_cliente" 
        
    }
    try{
        $nom_cliente = $nom_cliente + $dom_cliente
        $RegistroDNS = Resolve-DnsName $nom_cliente -ErrorAction Stop
    }catch{
        $Status = $Error[0].Exception.Message
        return $Status
    }
    return $RegistroDNS
}

function Check-OUClienteASP ($nom_cliente, $Base_OU)
{
    
    try{
        
        $OU_Encontrada = Get-ADOrganizationalUnit -Filter * -SearchBase $Base_OU -ErrorAction Stop | Where-Object {$_.Name -eq $nom_cliente}
        
    }catch{
        $Status = $Error[0].Exception.Message
        return $Status
    }
    
    return $OU_Encontrada
    
    
}



function Check-SMBAccessClienteASP ($nom_cliente, $nom_server)
{
    
    $setting = get-wmiobject -Class Win32_LogicalShareSecuritySetting -filter "Name='$nom_cliente'" -ComputerName $nom_server

    $Acceso_Encontrado = $setting.GetSecurityDescriptor().Descriptor.Dacl | 
    Select @{Name="Domain";Expression={$_.Trustee.Domain}},
    @{Name="Name";Expression={$_.Trustee.Name}},
    @{Name="Access";Expression={ ConvertFrom-AccessMask $_.AccessMask}} 

    

    $ACL = "Usuarios" + $nom_cliente
    if ($Acceso_Encontrado[0].Name -eq $ACL){
         return $Acceso_Encontrado
    }else{
        
        return ""
    }
   
    
    
}

#Check-SMBAccessClienteASP Breves Nevermind03

<#
.Synopsis
   Descripción corta
.DESCRIPTION
   Descripción larga
.EXAMPLE
   Ejemplo de cómo usar este cmdlet
.EXAMPLE
   Otro ejemplo de cómo usar este cmdlet
#>
function Check-ServerASP
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Lista de servidores a verificar
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
                   [Alias('ComputerName')]
        [string[]]$Name
        #####Cambio#####
        #####Cambio2####
        
    )

    Begin
    {
        $PathClientes = "F:\Clientes\"
        $NombreDominio = ".neuralsoft.com.ar"
    }
    Process
    {
        foreach ($Servidor in $Computername){
            $EstadoServidor = @()
            $FunctionOut = @()
            $NombreServidor = $Servidor
            Write-Host "Verificando el servidor: $NombreServidor" -ForegroundColor Green
            try{
                $cim = New-CimSession -ComputerName $NombreServidor -ErrorAction Stop
            }catch{
                $LastLogonDate = Get-ADComputer -Identity $NombreServidor -Properties * | Select-Object LastLogonDate
                Write-Host "No se pudo conectar al servidor $NombreServidor" -ForegroundColor Red
                Write-Host "Ultimo logon de este equipo: $LastLogonDate" -ForegroundColor Red
                continue
            }
            #$RecursosCompartidos = Get-SmbShare -CimSession $cim -Special $false -IncludeHidden | Where-Object {$_.Name -notlike "*$" }
            [array]$RecursosCompartidos = GET-WMIOBJECT Win32_Share  -ComputerName $NombreServidor | Where-Object {$_.Name -notlike "*$" }
            $Actividad = 0

            $RecursosCompartidos | ForEach-Object{
                Write-Progress -Activity "Verificando el servidor $NombreServidor" -PercentComplete $Actividad -Status "Espere..."
                $Actividad = $Actividad + (100/$RecursosCompartidos.count)

                $RecursoCompartido = $_
                
                #Creo el objeto del estado
                $EstadoRecurso = New-Object System.Object
                $EstadoRecurso | Add-Member -type NoteProperty -name Recurso -Value $RecursoCompartido.Name
                
                #Verifico estado de DNS
                Write-Verbose "Verificando configuración DNS..." 
                $ResultadoDNS = Check-NameClienteASP $RecursoCompartido.Name $NombreDominio
                if ($ResultadoDNS.gettype().Name -eq "String"){
                    Write-Verbose $ResultadoDNS
                    $EstadoRecurso | Add-Member -type NoteProperty -name DNS -Value "FAIL"
                }else{
                    #TO-DO!!!!!!!!!: Verificar que el DNS resuelva el mismo server que se está controlando
                    #Write-Host $ResultadoDNS[0].Name
                    #Write-Host $ResultadoDNS[0].NameHost
                    #Write-Host $Servidor
                    if ($ResultadoDNS[0].NameHost -eq $NombreServidor+$NombreDominio){
                    $EstadoRecurso | Add-Member -type NoteProperty -name DNS -Value "OK"
                    }else{
                        Write-Verbose "Nombre DNS: $ResultadoDNS[0].NameHost"
                        Write-Verbose "Nombre de servidor: ($Servidor+$NombreDominio)"
                        $EstadoRecurso | Add-Member -type NoteProperty -name DNS -Value "FAIL"
                    }
                }

                #Verifico estado de path
                Write-Verbose "Verificando configuración del Path..." 
                $Path_Encontrado = $RecursoCompartido.Path
                $Path_Baseline = $PathClientes + $RecursoCompartido.Name
                if ($Path_Encontrado -eq $Path_Baseline){
                    $EstadoRecurso | Add-Member -type NoteProperty -name PATH -Value "OK"
                }else{
                    Write-Verbose "Path con error: $Path_Encontrado"
                    $EstadoRecurso | Add-Member -type NoteProperty -name PATH -Value "FAIL"
                }

                #Verifico OU
                Write-Verbose "Verificando configuración OU..."
                $OU_Encontrada = Check-OUClienteASP $RecursoCompartido.Name "OU=ClientesASP,DC=neuralsoft,DC=com,DC=ar"
                if ($OU_Encontrada){
                    $EstadoRecurso | Add-Member -type NoteProperty -name OU -Value "OK"
                }else{
                    Write-Verbose "No existe la OU $RecursoCompartido.Name"
                    $EstadoRecurso | Add-Member -type NoteProperty -name OU -Value "FAIL"
                }

                #Verifico Acceso SMB
                Write-Verbose "Verificando configuración Acceso a Recurso Compartido..." 
                $AccesoSMB_Encontrado = Check-SMBAccessClienteASP $RecursoCompartido.Name $NombreServidor
                if ($AccesoSMB_Encontrado){
                    $EstadoRecurso | Add-Member -type NoteProperty -name AccesoSMB -Value "OK"
                }else{
                    Write-Verbose "Error en la asignación de permisos a nivel de recurso compartido"
                    $EstadoRecurso | Add-Member -type NoteProperty -name AccesoSMB -Value "FAIL"
                }

                #Verifico Acceso NTFS
                Write-Verbose "Verificando configuración Acceso NTFS..." 
                $ACL_UsuarioEmpresa = "NEURALSOFT\Usuarios" + $RecursoCompartido.Name
                
                try{
                    $AccesoNTFS_Encontrado = Invoke-Command -Computer $NombreServidor -ScriptBlock {param($Path) get-acl $Path  | select -expand access }  -ArgumentList $Path_Encontrado -ErrorAction Stop
                }catch{

                }
                $AccesoNTFS_Baseline = @("NT AUTHORITY\SYSTEM","BUILTIN\Administradores", "BUILTIN\Operadores de copia de seguridad", "NEURALSOFT\Soporte Nevermind", $ACL_UsuarioEmpresa)
                
                $AccessDif = Compare-Object   $AccesoNTFS_Baseline $AccesoNTFS_Encontrado.IdentityReference
                if (-not $AccessDif){
                    $EstadoRecurso | Add-Member -type NoteProperty -name AccesoNTFS -Value "OK"
                }else{
                    Write-Verbose "Error en la asignación de permisos a nivel NTFS"
                    $EstadoRecurso | Add-Member -type NoteProperty -name AccesoNTFS -Value "FAIL"
                }

                #Verifico 1:1 Shared/Clientes
                Write-Verbose "Verificando configuración relación 1:1 Carpera/Sharing..." 
                $CarpetasEncontradas = ""
                $CarpetasEncontradas = Invoke-Command -Computer $NombreServidor -ScriptBlock {param($Path) if (Test-Path $Path){Get-ChildItem $Path}   }  -ArgumentList $PathClientes 
                if ($CarpetasEncontradas){
                    $CarperaShareDif = Compare-Object   $CarpetasEncontradas.Name $RecursosCompartidos.Name 
                }

            $EstadoServidor += $EstadoRecurso
            }
            
            if ($CarperaShareDif){
            Write-Host "Existe esta inconsistencia entre las carpetas y los recursos compartidos: "
            Write-Host ""
            Write-Host $CarperaShareDif.InputObject -ForegroundColor Red
            Write-Host ""
        }
        Write-Host "Estado del servidor $NombreServidor"
        Write-Host ""
        $EstadoServidor

        $FunctionOut += $EstadoServidor
            
            Remove-CimSession -CimSession $cim

        }
    }
    End
    {
        Write-Output $FunctionOut
    }
}


#Check-ServerASP nevermind027 | ft
#Check-ServerASP nevermind0241 | ft