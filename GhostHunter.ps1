param(
    [string]$Equipo = $env:COMPUTERNAME
)

$equipoInicial = $Equipo  # Leemos lo que nos pasen
if (-not $equipoInicial) {
    $equipoInicial = $env:COMPUTERNAME
}

#region BLOQUE - FUNCIONES DE ANÁLISIS DE PERFILES

function Get-UltimoLogonExitoso {
    param(
        [string]$Usuario,
        [string]$Equipo = $env:COMPUTERNAME
    )

    try {
        # Event IDs para logon exitoso: 4624 - An account was successfully logged on
        # Filtrar por logon types: 2 (Interactive), 10 (RemoteInteractive), 11 (CachedInteractive)
        
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624)]]
      and
      *[EventData[Data[@Name='TargetUserName'] and (Data='$Usuario')]]
      and
      *[EventData[Data[@Name='LogonType'] and (Data='2' or Data='10' or Data='11')]]
    </Select>
  </Query>
</QueryList>
"@

        # Obtener el evento más reciente (último logon exitoso)
        $eventos = Get-WinEvent -ComputerName $Equipo -FilterXml $filterXml -MaxEvents 1 -ErrorAction Stop
        
        if ($eventos) {
            return $eventos[0].TimeCreated
        } else {
            return $null
        }
        
    } catch [System.Exception] {
        if ($_.Exception.Message -like "*No events were found*") {
            # No se encontraron eventos de logon para este usuario
            return $null
        } elseif ($_.Exception.Message -like "*Access is denied*") {
            # Sin permisos para acceder a logs de seguridad
            return $null
        } else {
            # Cualquier otro error
            return $null
        }
    }
}

function Get-FechaCreacionPerfil {
    param(
        [string]$SID,
        [string]$Equipo = $env:COMPUTERNAME
    )
    
    try {
        $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Equipo)
        $SubKey = $RegKey.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID")
        
        if ($SubKey) {
            # Intentar obtener ProfileLoadTime (más preciso si está disponible)
            $profileLoadTime = $SubKey.GetValue("ProfileLoadTime")
            if ($profileLoadTime) {
                try {
                    # Convertir de FILETIME a DateTime
                    $fileTime = [System.BitConverter]::ToInt64($profileLoadTime, 0)
                    $RegKey.Close()
                    return [DateTime]::FromFileTime($fileTime)
                } catch {
                    # Si falla la conversión, continuar con el método alternativo
                }
            }
            
            # Fallback: usar fecha de la carpeta del perfil
            $rutaPerfil = $SubKey.GetValue("ProfileImagePath")
            if ($rutaPerfil) {
                $rutaUNC = $rutaPerfil -replace "^[a-zA-Z]:", "\\$Equipo\C$"
                if (Test-Path $rutaUNC) {
                    $RegKey.Close()
                    return (Get-Item $rutaUNC -ErrorAction SilentlyContinue).CreationTime
                }
            }
        }
        $RegKey.Close()
        return $null
        
    } catch {
        return $null
    }
}

function Get-PerfilesLocales {
    param(
        [string]$Equipo = $env:COMPUTERNAME
    )

    # Exclusiones exactas (comparación con -contains)
    $excluirExacto = @(
        'Default', 'Default User', 'Public', 'All Users', 'desktop.ini',
        'Administrador', 'Administrator', 'systemprofile', 'LocalService', 'NetworkService',
        'SYSTEM', 'Invitado', 'Guest', 'WDAGUtilityAccount', 'Administrador de la empresa',
        'DefaultAccount', 'ADMIN', 'ADMIN$',
        'appmodel', 'sshd', 'ssh', 'DWM-1', 'UMFD-0', 'UMFD-1',
        'DefaultAppPool', 'Classic .NET AppPool',
        '.NET v2.0', '.NET v4.0', '.NET v4.5', '.NET v4.5 Classic', '.NET v2.0 Classic', '.NET CLR',
        'Symantec', 'Symantec Task Server', 'Symantec Task Server AppPool',
        'Sophos', 'McAfee', 'TrendMicro', 'ESET',
        'SQLServer', 'SQLAgent', 'ReportServer', 'AppFabric', 'Ssms', 'W3SVC', 'IIS_IUSRS',
        'TEMP', 'TEMPUSER', 'tsclient', 'UPNROAM', 'RECOVERY', 'UpdatusUser', 'OneDriveTemp',
        'HomeGroupUser$', 'SAPService', 'hpuser',
        'MicrosoftWindows.Client.CBS_cw5n1h2txyewy', 'aorgon',
        'ASPNET', 'IIS AppPool', 'IIS_WPG', 'IUSR',
        'krbtgt', 'SQLServerReportServerUser', 'SQLServerSQLAgentUser', 'MSSQLSERVER',
        'Exchange Organization Administrator', 'Exchange Recipient Administrator',
        'Exchange Public Folder Administrator', 'Exchange View-Only Administrator'
    )

    # Patrones wildcard (se evalúan con -like, NO con -contains)
    $excluirWildcard = @(
        'S-1-5-*', 'svc_*', 'SUPPORT_*',
        'aorgon.DESKTOP-*', 'aorgon.SERVIDOR-*',
        'IWAM_*', 'VUSR_*',
        'HealthMailbox*', 'FederatedEmail.*', 'SystemMailbox*', 'DiscoverySearchMailbox*',
        'Migration.*', 'TEMP.*', 'TMP.*', 'Temp.*', 'Tmp.*'
    )

    $perfiles = @()
    $perfilesBasicos = @()
    $usoCIM = $false

    # ── MÉTODO RÁPIDO: CIM Win32_UserProfile ──
    # Una sola consulta obtiene SID, LastUseTime, Loaded (en uso), Special (cuenta sistema)
    try {
        $cimPerfiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $Equipo -ErrorAction Stop |
            Where-Object { -not $_.Special -and $_.LocalPath -like 'C:\Users\*' }

        $usoCIM = $true

        foreach ($cim in $cimPerfiles) {
            $nombre = [System.IO.Path]::GetFileName($cim.LocalPath)

            # Exclusión exacta
            if ($excluirExacto -contains $nombre) { continue }

            # Exclusión por wildcard (evaluada correctamente con -like)
            $excluido = $false
            foreach ($patron in $excluirWildcard) {
                if ($nombre -like $patron) { $excluido = $true; break }
            }
            if ($excluido) { continue }

            # LastUseTime de CIM es instantáneo vs Event Log (10-30s por perfil)
            $ultimoLogon = $cim.LastUseTime
            if (-not $ultimoLogon) {
                $ultimoLogon = Get-FechaCreacionPerfil -SID $cim.SID -Equipo $Equipo
            }
            if (-not $ultimoLogon) {
                $ultimoLogon = (Get-Date).AddDays(-365)
            }

            $perfilesBasicos += [PSCustomObject]@{
                Usuario     = $nombre
                Ruta        = $cim.LocalPath
                SID         = $cim.SID
                UltimoLogon = $ultimoLogon
                Loaded      = $cim.Loaded
            }
        }
    }
    catch {
        # ── FALLBACK: Método por registro (más lento pero compatible) ──
        Write-Warning "CIM no disponible en $Equipo, usando método de registro..."
        try {
            $RutaPerfiles = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Equipo)
            $SubKey = $RegKey.OpenSubKey($RutaPerfiles)

            foreach ($SID in $SubKey.GetSubKeyNames()) {
                try {
                    $SubClave = $SubKey.OpenSubKey($SID)
                    $rutaPerfil = $SubClave.GetValue("ProfileImagePath")
                    if ([string]::IsNullOrWhiteSpace($rutaPerfil)) { continue }
                    if ($rutaPerfil -notlike 'C:\Users\*') { continue }

                    $nombre = [System.IO.Path]::GetFileName($rutaPerfil)
                    if ($excluirExacto -contains $nombre) { continue }

                    $excluido = $false
                    foreach ($patron in $excluirWildcard) {
                        if ($nombre -like $patron) { $excluido = $true; break }
                    }
                    if ($excluido) { continue }

                    $ultimoLogon = Get-FechaCreacionPerfil -SID $SID -Equipo $Equipo
                    if (-not $ultimoLogon) {
                        $ultimoLogon = (Get-Date).AddDays(-365)
                    }

                    $perfilesBasicos += [PSCustomObject]@{
                        Usuario     = $nombre
                        Ruta        = $rutaPerfil
                        SID         = $SID
                        UltimoLogon = $ultimoLogon
                        Loaded      = $false
                    }
                } catch { continue }
            }
            $RegKey.Close()
        }
        catch {
            Write-Warning "No se pudo acceder al registro remoto de $Equipo. Error: $_"
            return @()
        }
    }

    if ($perfilesBasicos.Count -eq 0) { return @() }

    # ── CÁLCULO DE TAMAÑO EN JOBS PARALELOS ──
    # Usa .NET EnumerateFiles (más rápido que Get-ChildItem -Recurse)
    $jobs = @()
    $batchSize = 5

    for ($i = 0; $i -lt $perfilesBasicos.Count; $i += $batchSize) {
        $endIndex = [Math]::Min($i + $batchSize - 1, $perfilesBasicos.Count - 1)
        $batchPerfiles = $perfilesBasicos[$i..$endIndex]

        $job = Start-Job -ScriptBlock {
            param($batchParam, $EquipoParam)

            $resultados = @()
            foreach ($perfil in $batchParam) {
                $tamano = 0
                try {
                    $rutaUNC = $perfil.Ruta -replace "^[a-zA-Z]:", "\\$EquipoParam\C`$"
                    if (Test-Path $rutaUNC) {
                        try {
                            # .NET EnumerateFiles es más rápido que Get-ChildItem
                            $archivos = [System.IO.Directory]::EnumerateFiles(
                                $rutaUNC, '*', [System.IO.SearchOption]::AllDirectories)
                            foreach ($archivo in $archivos) {
                                try { $tamano += ([System.IO.FileInfo]::new($archivo)).Length } catch { }
                            }
                        }
                        catch {
                            # Fallback si EnumerateFiles falla (permisos parciales)
                            $items = @(Get-ChildItem -Path $rutaUNC -Recurse -File -Force -ErrorAction SilentlyContinue)
                            if ($items.Count -gt 0) {
                                $suma = ($items | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                                if ($null -ne $suma -and $suma -ge 0) { $tamano = $suma }
                            }
                        }
                    }
                } catch { }

                $resultados += [PSCustomObject]@{
                    Usuario = $perfil.Usuario
                    Tamano  = $tamano
                }
            }
            return $resultados
        } -ArgumentList @(,$batchPerfiles), $Equipo

        $jobs += $job
    }

    # Esperar con timeout de 5 minutos
    $jobs | Wait-Job -Timeout 300 | Out-Null

    # Recopilar tamaños
    $mapaTamanos = @{}
    foreach ($job in $jobs) {
        if ($job.State -eq 'Completed') {
            $res = Receive-Job -Job $job
            foreach ($r in $res) {
                if ($r -and $r.Usuario) { $mapaTamanos[$r.Usuario] = $r.Tamano }
            }
        }
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }

    # ── CLASIFICAR PERFILES ──
    foreach ($perfil in $perfilesBasicos) {
        $tamanoBytes = if ($mapaTamanos.ContainsKey($perfil.Usuario)) { $mapaTamanos[$perfil.Usuario] } else { 0 }
        $diasSinLogon = ((Get-Date) - $perfil.UltimoLogon).Days
        $esPequeno = $tamanoBytes -lt 1GB
        $esAntiguo = $perfil.UltimoLogon -lt (Get-Date).AddDays(-91)  # > 3 meses
        $inactivoMinimo = $diasSinLogon -gt 30  # > 1 mes

        if ($perfil.Loaded) {
            # PROTECCIÓN: perfil cargado en memoria (usuario conectado)
            $estado = "Protegido (perfil en uso)"
        }
        elseif ($esPequeno -and $esAntiguo) {
            $estado = "Eliminable (< 1GB y $diasSinLogon días sin uso)"
        }
        elseif ($esAntiguo) {
            $estado = "Eliminable ($diasSinLogon días sin uso)"
        }
        elseif ($esPequeno -and $inactivoMinimo) {
            # Solo marcar pequeños si llevan al menos 30 días sin uso
            $estado = "Eliminable (< 1GB y $diasSinLogon días sin uso)"
        }
        else {
            $estado = "Activo (usado recientemente)"
        }

        $perfiles += [PSCustomObject]@{
            Usuario     = $perfil.Usuario
            Ruta        = $perfil.Ruta
            UltimoLogon = $perfil.UltimoLogon
            TamanoBytes = $tamanoBytes
            SID         = $perfil.SID
            Estado      = $estado
        }
    }

    return $perfiles
}

#endregion

#region BLOQUE - CARGAR PERFILES EN LA INTERFAZ

function Cargar-PerfilesEnLista {
    param (
        [string]$EquipoObjetivo
    )

    $listView.Items.Clear()

    $resultados = Get-PerfilesLocales -Equipo $EquipoObjetivo

    $global:PerfilesCargados = $resultados

    Refrescar-ListViewFiltrado -Datos $resultados `
                               -FiltrarAntiguos $chkAntiguos.Checked `
                               -FiltrarPequenos $chkPequenos.Checked
}
#endregion

#region BLOQUE - FUNCIONES AUXILIARES

function Format-TamanoArchivo {
    param([long]$Bytes)
    
    # Mostrar en la unidad más apropiada (MB o GB)
    if ($Bytes -eq 0) {
        return "0.00 MB"
    }
    elseif ($Bytes -lt 1073741824) {
        # Menor a 1GB: mostrar en MB con precisión
        $mb = [Math]::Round($Bytes / 1048576.0, 2)  # 1MB = 1048576 bytes
        return "$mb MB"
    }
    else {
        # 1GB o mayor: mostrar en GB con precisión
        $gb = [Math]::Round($Bytes / 1073741824.0, 2)  # 1GB = 1073741824 bytes
        return "$gb GB"
    }
}

function Get-SolucionesError {
    param (
        [string]$TipoError,
        [string]$Usuario,
        [string]$Equipo
    )

    $soluciones = @()

    switch -Wildcard ($TipoError) {
        "*permisos*" {
            $soluciones += "💡 Ejecuta el script como Administrador"
            $soluciones += "💡 Verifica que tengas permisos de administrador en el equipo $Equipo"
        }
        "*en uso*" {
            $soluciones += "💡 Cierra todas las aplicaciones del usuario $Usuario"
            $soluciones += "💡 Verifica que el usuario no esté conectado actualmente"
            $soluciones += "💡 Reinicia el equipo si es necesario"
        }
        "*acceso denegado*" {
            $soluciones += "💡 Verifica permisos de red al equipo $Equipo"
            $soluciones += "💡 Usa credenciales de administrador de dominio"
        }
        "*no encontrada*" {
            $soluciones += "💡 El perfil ya puede haber sido eliminado"
            $soluciones += "💡 Verifica que el usuario $Usuario existe en el equipo $Equipo"
        }
        "*registry*" {
            $soluciones += "💡 Verifica permisos de acceso al registro"
            $soluciones += "💡 El perfil puede estar parcialmente eliminado"
        }
        default {
            $soluciones += "💡 Contacta al administrador del sistema"
            $soluciones += "💡 Revisa los logs de eventos de Windows"
        }
    }

    return $soluciones
}

function Verificar-EliminacionPerfil {
    param (
        [string]$Usuario,
        [string]$SID,
        [string]$Equipo
    )

    $estado = [PSCustomObject]@{
        Usuario = $Usuario
        SID = $SID
        RegistroEliminado = $false
        CarpetaEliminada = $false
        CarpetaOldExiste = $false
        EstadoGeneral = "Desconocido"
        Detalles = ""
    }

    # Verificar si la clave de registro existe
    try {
        $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Equipo)
        $clavePerfil = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
        $estado.RegistroEliminado = -not ($RegKey.OpenSubKey($clavePerfil))
        $RegKey.Close()
        $estado.Detalles += "Registro: $(if ($estado.RegistroEliminado) { 'Eliminado' } else { 'Existe' }); "
    }
    catch {
        $estado.RegistroEliminado = $null  # No se pudo verificar
        $estado.Detalles += "Registro: Error al verificar ($($_)); "
    }

    # Verificar si la carpeta original existe
    try {
        $rutaUNC = "\\$Equipo\C$\Users\$Usuario"
        $estado.CarpetaEliminada = -not (Test-Path $rutaUNC)
        $estado.Detalles += "Carpeta original: $(if ($estado.CarpetaEliminada) { 'No existe' } else { 'Existe' }); "
    }
    catch {
        $estado.CarpetaEliminada = $null  # No se pudo verificar
        $estado.Detalles += "Carpeta original: Error al verificar ($($_)); "
    }

    # Verificar si existe carpeta _old (significa que fue renombrada para eliminación)
    try {
        $rutaOld = "\\$Equipo\C$\Users\$($Usuario)_old"
        $estado.CarpetaOldExiste = Test-Path $rutaOld
        $estado.Detalles += "Carpeta _old: $(if ($estado.CarpetaOldExiste) { 'Existe' } else { 'No existe' }); "
    }
    catch {
        $estado.CarpetaOldExiste = $null
        $estado.Detalles += "Carpeta _old: Error al verificar ($($_)); "
    }

    # Determinar estado general con lógica mejorada
    if ($estado.RegistroEliminado -and $estado.CarpetaEliminada) {
        $estado.EstadoGeneral = "Completamente Eliminado"
    }
    elseif ($estado.RegistroEliminado -and $estado.CarpetaOldExiste) {
        $estado.EstadoGeneral = "Renombrado a _old, pendiente eliminación completa"
    }
    elseif ($estado.RegistroEliminado -and -not $estado.CarpetaEliminada -and -not $estado.CarpetaOldExiste) {
        $estado.EstadoGeneral = "Registro eliminado, carpeta intacta"
    }
    elseif (-not $estado.RegistroEliminado -and $estado.CarpetaEliminada) {
        $estado.EstadoGeneral = "Carpeta eliminada, registro pendiente"
    }
    elseif (-not $estado.RegistroEliminado -and $estado.CarpetaOldExiste) {
        $estado.EstadoGeneral = "Carpeta renombrada, registro intacto"
    }
    else {
        $estado.EstadoGeneral = "Sin eliminar"
    }

    return $estado
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Forzar-EliminarCarpeta {
    param([string]$PathUNC)

    Write-Host "🔄 Iniciando eliminación robusta de: $PathUNC"

    # Verificar permisos de administrador
    $isAdmin = Test-Administrator
    if (-not $isAdmin) {
        Write-Warning "⚠ ADVERTENCIA: No tienes permisos de Administrador"
        Write-Host "💡 Recomendación: Ejecuta el script como Administrador para mejores resultados"
    }

    # Verificar si la carpeta existe
    if (-not (Test-Path $PathUNC)) {
        Write-Host "✅ La carpeta ya no existe: $PathUNC"
        return $true
    }    # Verificar si hay procesos usando archivos en la carpeta
    try {
        $procesosUsando = Get-Process | Where-Object {
            $_.Modules | Where-Object { $_.FileName -like "$PathUNC*" }
        }
        if ($procesosUsando) {
            Write-Warning "⚠ ADVERTENCIA: La carpeta está siendo usada por procesos:"
            foreach ($proceso in $procesosUsando) {
                Write-Warning "   - $($proceso.Name) (PID: $($proceso.Id))"
            }
            Write-Host "💡 Recomendación: Cierra estos procesos antes de continuar"
        }
    }
    catch {
        # No se pudo verificar procesos, continuar
    }

    # Obtener información del tamaño para ajustar estrategia
    try {
        $tamanoTotal = (Get-ChildItem -Path $PathUNC -Recurse -ErrorAction SilentlyContinue | 
                       Measure-Object -Property Length -Sum).Sum
        $tamanoGB = [Math]::Round($tamanoTotal / 1GB, 2)
        Write-Host "📊 Tamaño detectado: $tamanoGB GB"
    }
    catch {
        $tamanoGB = 0
        Write-Host "⚠ No se pudo calcular el tamaño, continuando..."
    }

    # PASO 1: Eliminar archivos por lotes para perfiles grandes
    if ($tamanoGB -gt 2) {
        Write-Host "🔄 Perfil grande detectado. Eliminando archivos por lotes..."
        
        try {
            # Eliminar archivos en subcarpetas problemáticas primero
            $carpetasProblematicas = @(
                "AppData\Local\Temp",
                "AppData\Local\Microsoft\Windows\INetCache",
                "AppData\Local\Google\Chrome\User Data\Default\Cache",
                "AppData\Local\Microsoft\Edge\User Data\Default\Cache",
                "AppData\Roaming\Microsoft\Windows\Recent",
                "Downloads",
                "Desktop"
            )

            foreach ($subcarpeta in $carpetasProblematicas) {
                $rutaSubcarpeta = Join-Path $PathUNC $subcarpeta
                if (Test-Path $rutaSubcarpeta) {
                    Write-Host "🗑️ Limpiando: $subcarpeta"
                    try {
                        Get-ChildItem -Path $rutaSubcarpeta -Recurse -File -ErrorAction SilentlyContinue | 
                        ForEach-Object {
                            try {
                                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                            }
                            catch {
                                # Archivo bloqueado, continuar
                            }
                        }
                    }
                    catch {
                        Write-Warning "⚠ Error limpiando $subcarpeta"
                    }
                }
            }
        }
        catch {
            Write-Warning "⚠ Error en limpieza por lotes: $_"
        }
    }

    # PASO 2: Intentar eliminación con PowerShell (método estándar)
    Write-Host "🔄 Intento 1: Remove-Item con PowerShell..."
    try {
        Remove-Item -Path $PathUNC -Recurse -Force -ErrorAction Stop
        Write-Host "✅ Carpeta eliminada con Remove-Item: $PathUNC"
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*Access is denied*" -or $errorMsg -like "*Access denied*") {
            Write-Warning "❌ Remove-Item falló por permisos insuficientes: $errorMsg"
            Write-Host "💡 Solución: Ejecuta el script como Administrador"
        }
        elseif ($errorMsg -like "*being used by another process*" -or $errorMsg -like "*in use*") {
            Write-Warning "❌ Remove-Item falló porque archivos están en uso: $errorMsg"
            Write-Host "💡 Solución: Cierra aplicaciones que puedan estar usando archivos del perfil"
        }
        else {
            Write-Warning "❌ Remove-Item falló: $errorMsg"
        }
    }

    # PASO 3: Intentar con ROBOCOPY (muy efectivo para carpetas grandes)
    Write-Host "🔄 Intento 2: ROBOCOPY con carpeta vacía..."
    try {
        # Crear carpeta temporal vacía
        $tempEmpty = Join-Path $env:TEMP "EmptyFolder_$(Get-Random)"
        New-Item -Path $tempEmpty -ItemType Directory -Force | Out-Null
        
        # Usar ROBOCOPY para "sincronizar" con carpeta vacía (elimina todo)
        $equipo = ($PathUNC -split "\\")[2]
        $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"
        
        if ($equipo -eq $env:COMPUTERNAME) {
            # Local
            $roboResult = robocopy $tempEmpty $rutaLocal /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS 2>$null
        }
        else {
            # Remoto - usar UNC
            $roboResult = robocopy $tempEmpty $PathUNC /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS 2>$null
        }
        
        # Limpiar carpeta temporal
        Remove-Item -Path $tempEmpty -Force -ErrorAction SilentlyContinue
        
        # Verificar si ROBOCOPY funcionó
        if (-not (Test-Path $PathUNC) -or (Get-ChildItem -Path $PathUNC -ErrorAction SilentlyContinue).Count -eq 0) {
            # Eliminar la carpeta vacía restante
            try {
                Remove-Item -Path $PathUNC -Force -ErrorAction SilentlyContinue
                Write-Host "✅ Carpeta eliminada con ROBOCOPY: $PathUNC"
                return $true
            }
            catch {
                Write-Warning "⚠ ROBOCOPY vació la carpeta pero no se pudo eliminar el contenedor"
            }
        }
    }
    catch {
        Write-Warning "❌ ROBOCOPY falló: $_"
    }

    # PASO 4: Intentar con CMD (rd /s /q)
    Write-Host "🔄 Intento 3: CMD rd /s /q..."
    try {
        $equipo = ($PathUNC -split "\\")[2]
        $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"
        
        if ($equipo -eq $env:COMPUTERNAME) {
            # Local
            $cmd = "rd /s /q `"$rutaLocal`""
        }
        else {
            # Remoto
            $escapedPath = $PathUNC -replace '"', '""'
            $cmd = "rd /s /q `"$escapedPath`""
        }
        
        $result = cmd.exe /c $cmd 2>$null
        
        if (-not (Test-Path $PathUNC)) {
            Write-Host "✅ Carpeta eliminada con CMD: $PathUNC"
            return $true
        }
        else {
            Write-Warning "❌ CMD no pudo eliminar completamente la carpeta"
        }
    }
    catch {
        Write-Warning "❌ CMD falló: $_"
    }

    # PASO 5: Intentar con takeown y icacls (para problemas de permisos)
    Write-Host "🔄 Intento 4: Tomar propiedad y cambiar permisos..."
    try {
        $equipo = ($PathUNC -split "\\")[2]
        $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"

        if ($equipo -eq $env:COMPUTERNAME) {
            # Tomar propiedad recursivamente
            $takeownResult = takeown /f $rutaLocal /r /d y 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "⚠ takeown falló: $takeownResult"
            }

            # Dar permisos completos a administradores
            $icaclsResult = icacls $rutaLocal /grant administrators:F /t /c /q 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "⚠ icacls falló: $icaclsResult"
            }

            # Intentar eliminar de nuevo
            Remove-Item -Path $rutaLocal -Recurse -Force -ErrorAction Stop

            Write-Host "✅ Carpeta eliminada tras tomar propiedad: $PathUNC"
            return $true
        }
    }
    catch {
        Write-Warning "❌ Tomar propiedad falló: $_"
    }

    # PASO 6: Intentar con PowerShell como administrador (si es posible)
    Write-Host "🔄 Intento 5: PowerShell con credenciales elevadas..."
    try {
        $equipo = ($PathUNC -split "\\")[2]
        $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"

        if ($equipo -eq $env:COMPUTERNAME) {
            # Intentar con Start-Process como administrador
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "powershell.exe"
            $psi.Arguments = "-Command `"Remove-Item -Path '$rutaLocal' -Recurse -Force`""
            $psi.Verb = "runas"  # Ejecutar como administrador
            $psi.WindowStyle = "Hidden"
            $psi.UseShellExecute = $true

            $process = [System.Diagnostics.Process]::Start($psi)
            $process.WaitForExit(30000)  # Esperar máximo 30 segundos

            if ($process.ExitCode -eq 0 -and -not (Test-Path $rutaLocal)) {
                Write-Host "✅ Carpeta eliminada con PowerShell Admin: $PathUNC"
                return $true
            }
            else {
                Write-Warning "❌ PowerShell Admin no pudo eliminar la carpeta (ExitCode: $($process.ExitCode))"
            }
        }
    }
    catch {
        Write-Warning "❌ PowerShell Admin falló: $_"
    }

    # PASO 7: Registrar para eliminación tras reinicio
    Write-Host "🔄 Intento 6: Registrar para eliminación tras reinicio..."
    try {
        $equipo = ($PathUNC -split "\\")[2]
        $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"

        $clave = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $equipo)
        $sessionKey = $clave.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager", $true)

        if ($sessionKey) {
            $pendientes = $sessionKey.GetValue("PendingFileRenameOperations", @())
            $nuevoValor = $pendientes + @($rutaLocal, "")
            $sessionKey.SetValue("PendingFileRenameOperations", $nuevoValor, [Microsoft.Win32.RegistryValueKind]::MultiString)
            $sessionKey.Close()

            Write-Host "🕒 Carpeta registrada para eliminación tras reinicio: $rutaLocal"
            Write-Host "⚠ IMPORTANTE: Se requiere reinicio del equipo '$equipo' para completar la eliminación"
            Write-Host "💡 Después del reinicio, la carpeta se eliminará automáticamente"
            return $true
        }
        $clave.Close()
    }
    catch {
        Write-Warning "❌ Error registrando para eliminación tras reinicio: $_"
    }

    # ÚLTIMO RECURSO: Crear script de eliminación para ejecutar manualmente
    Write-Host "🔄 Último recurso: Creando script de eliminación manual..."
    try {
        $equipo = ($PathUNC -split "\\")[2]
        $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"

        $scriptPath = Join-Path $env:TEMP "Eliminar_Perfil_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
        $scriptContent = @"
# Script para eliminar perfil problemático
# Ejecutar como Administrador

Write-Host "Intentando eliminar: $rutaLocal"

# Método 1: takeown + icacls + remove
try {
    takeown /f "$rutaLocal" /r /d y
    icacls "$rutaLocal" /grant administrators:F /t /c
    Remove-Item -Path "$rutaLocal" -Recurse -Force
    Write-Host "✅ Eliminado exitosamente"
    exit 0
}
catch {
    Write-Host "❌ Error: `$_"
}

# Método 2: Usar rmdir /s /q
try {
    cmd.exe /c "rmdir /s /q `"$rutaLocal`""
    Write-Host "✅ Eliminado con CMD"
    exit 0
}
catch {
    Write-Host "❌ Error con CMD: `$_"
}

Write-Host "❌ No se pudo eliminar. Puede requerir reinicio del sistema."
"@

        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
        Write-Host "📄 Script creado en: $scriptPath"
        Write-Host "💡 Ejecuta este script como Administrador para intentar eliminar manualmente"
    }
    catch {
        Write-Warning "❌ Error creando script de eliminación: $_"
    }

    Write-Warning "❌ No se pudo eliminar la carpeta con ningún método: $PathUNC"
    Write-Host ""
    Write-Host "🔍 POSIBLES SOLUCIONES:"
    Write-Host "   1. Reinicia el equipo (la carpeta se eliminará automáticamente)"
    Write-Host "   2. Ejecuta el script creado como Administrador"
    Write-Host "   3. Verifica que no haya procesos usando archivos del perfil"
    Write-Host "   4. Contacta al administrador del sistema si persiste el problema"
    Write-Host ""

    return $false
}


#endregion

#region BLOQUE - LIMPIEZA DE ARCHIVOS TEMPORALES Y HUÉRFANOS

function Limpiar-ArchivosTemporales {
    param(
        [string]$Equipo = $env:COMPUTERNAME
    )

    $resultados = @()
    $totalEliminado = 0

    # Ubicaciones a limpiar
    $ubicaciones = @(
        @{
            Nombre = "Windows Installer"
            Ruta = "C:\Windows\Installer"
            Descripcion = "Archivos de instalación huérfanos"
            Patron = "*.msi;*.msp;*.tmp"
        },
        @{
            Nombre = "Windows Temp"
            Ruta = "C:\Windows\Temp"
            Descripcion = "Archivos temporales del sistema"
            Patron = "*.*"
        },
        @{
            Nombre = "Windows CBS Logs"
            Ruta = "C:\Windows\Logs\CBS"
            Descripcion = "Logs antiguos de CBS"
            Patron = "*.log;*.cab"
        }
    )

    # Procesar ubicaciones en paralelo para mayor velocidad
    $jobsLimpieza = @()
    
    foreach ($ubicacion in $ubicaciones) {
        $job = Start-Job -ScriptBlock {
            param($ubicacionParam, $EquipoParam)
            
            $archivosEliminados = 0
            $tamanoEliminado = 0
            
            try {
                $rutaUNC = "\\$EquipoParam\C$\" + $ubicacionParam.Ruta.Substring(3)
                
                if (Test-Path $rutaUNC) {
                    $patrones = $ubicacionParam.Patron -split ";"
                    
                    # Usar Where-Object para filtrar más eficientemente
                    $archivosAVerificar = Get-ChildItem -Path $rutaUNC -Recurse -File -ErrorAction SilentlyContinue
                    
                    foreach ($patron in $patrones) {
                        $archivos = $archivosAVerificar | Where-Object { 
                            $_.Name -like $patron -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) 
                        }
                        
                        foreach ($archivo in $archivos) {
                            try {
                                $tamano = $archivo.Length
                                Remove-Item -Path $archivo.FullName -Force -ErrorAction Stop
                                $archivosEliminados++
                                $tamanoEliminado += $tamano
                            }
                            catch {
                                # Archivo en uso o sin permisos, continuar
                            }
                        }
                    }
                }
            }
            catch {
                # Error accediendo a la ubicación
            }
            
            return [PSCustomObject]@{
                Ubicacion = $ubicacionParam.Nombre
                Descripcion = $ubicacionParam.Descripcion
                ArchivosEliminados = $archivosEliminados
                TamanoEliminado = $tamanoEliminado
                Estado = if ($archivosEliminados -gt 0) { "✓ Completado" } else { "⚠ Sin archivos para eliminar" }
            }
        } -ArgumentList $ubicacion, $Equipo
        
        $jobsLimpieza += $job
    }
    
    # Esperar a que terminen todos los jobs de limpieza
    $jobsLimpieza | Wait-Job | Out-Null
    
    # Recopilar resultados
    foreach ($job in $jobsLimpieza) {
        $resultado = Receive-Job -Job $job
        $resultados += $resultado
        $totalEliminado += $resultado.TamanoEliminado
        Remove-Job -Job $job
    }

    return [PSCustomObject]@{
        Resultados = $resultados
        TotalEliminadoMB = [Math]::Round($totalEliminado / 1MB, 2)
    }
}function Limpiar-CacheUsuarios {
    param(
        [string]$Equipo = $env:COMPUTERNAME
    )

    $resultados = @()
    $totalEliminado = 0

    try {
        $rutaUsuarios = "\\$Equipo\C$\Users"
        
        if (Test-Path $rutaUsuarios) {
            $usuarios = Get-ChildItem -Path $rutaUsuarios -Directory -ErrorAction SilentlyContinue | 
                       Where-Object { $_.Name -notin @('Public', 'Default', 'All Users') }

            # Procesar usuarios en paralelo
            $jobsUsuarios = @()
            
            foreach ($usuario in $usuarios) {
                $job = Start-Job -ScriptBlock {
                    param($usuarioParam, $EquipoParam)
                    
                    $cachesUsuario = @(
                        @{
                            Nombre = "Temp Local"
                            Ruta = "$($usuarioParam.FullName)\AppData\Local\Temp"
                            Patron = "*.*"
                        },
                        @{
                            Nombre = "Cache IE"
                            Ruta = "$($usuarioParam.FullName)\AppData\Local\Microsoft\Windows\INetCache"
                            Patron = "*.*"
                        },
                        @{
                            Nombre = "Cache Chrome"
                            Ruta = "$($usuarioParam.FullName)\AppData\Local\Google\Chrome\User Data\Default\Cache"
                            Patron = "*.*"
                        },
                        @{
                            Nombre = "Cache Edge"
                            Ruta = "$($usuarioParam.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Cache"
                            Patron = "*.*"
                        }
                    )

                    $archivosUsuario = 0
                    $tamanoUsuario = 0

                    foreach ($cache in $cachesUsuario) {
                        if (Test-Path $cache.Ruta) {
                            try {
                                # Obtener archivos una vez y filtrar en memoria
                                $archivos = Get-ChildItem -Path $cache.Ruta -Recurse -File -ErrorAction SilentlyContinue |
                                           Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-3) }
                                
                                foreach ($archivo in $archivos) {
                                    try {
                                        $tamano = $archivo.Length
                                        Remove-Item -Path $archivo.FullName -Force -ErrorAction Stop
                                        $archivosUsuario++
                                        $tamanoUsuario += $tamano
                                    }
                                    catch {
                                        # Archivo en uso, continuar
                                    }
                                }
                            }
                            catch {
                                # Error accediendo a la carpeta, continuar
                            }
                        }
                    }

                    return [PSCustomObject]@{
                        Usuario = $usuarioParam.Name
                        ArchivosEliminados = $archivosUsuario
                        TamanoEliminado = $tamanoUsuario
                        Estado = if ($archivosUsuario -gt 0) { "✓ Limpieza completada" } else { "⚠ Sin archivos para eliminar" }
                    }
                } -ArgumentList $usuario, $Equipo
                
                $jobsUsuarios += $job
            }
            
            # Esperar a que terminen todos los jobs de usuarios
            $jobsUsuarios | Wait-Job | Out-Null
            
            # Recopilar resultados
            foreach ($job in $jobsUsuarios) {
                $resultado = Receive-Job -Job $job
                if ($resultado.ArchivosEliminados -gt 0) {
                    $resultados += $resultado
                }
                $totalEliminado += $resultado.TamanoEliminado
                Remove-Job -Job $job
            }
        }
    }
    catch {
        $resultados += [PSCustomObject]@{
            Usuario = "Error general"
            ArchivosEliminados = 0
            TamanoEliminadoMB = 0
            Estado = "❌ Error: $_"
        }
    }

    return [PSCustomObject]@{
        Resultados = $resultados
        TotalEliminadoMB = [Math]::Round($totalEliminado / 1MB, 2)
    }
}

#endregion

#region BLOQUE - ELIMINACIÓN DE PERFIL COMPLETO (RENOMBRA Y BORRA FORZADO)

function Eliminar-PerfilCompleto {
    param (
        [string]$Equipo,
        [string]$RutaPerfil,
        [string]$SID,
        [string]$Usuario
    )

    $result = [PSCustomObject]@{
        Usuario  = $Usuario
        SID      = $SID
        Resultado = ""
        Error     = $false
        DetallesError = ""
    }

    Write-Host "🗑️ Procesando eliminación de perfil: $Usuario (SID: $SID)"

    # 1) Eliminar clave en ProfileList
    $resultadoRegistro = Remove-ClaveRegistro -Equipo $Equipo -SID $SID
    $result.Resultado += $resultadoRegistro

    if ($resultadoRegistro -like "*Error*") {
        $result.DetallesError += "Error al eliminar clave de registro. "
        Write-Warning "⚠ Error al eliminar clave de registro para $Usuario"
    }

    # 2) Renombrar la carpeta a _old
    $rutaUNC = $RutaPerfil -replace "^[a-zA-Z]:", "\\$Equipo\C$"
    if (Test-Path $rutaUNC) {
        $nombreActual = Split-Path $rutaUNC -Leaf
        $carpetaPadre = Split-Path $rutaUNC -Parent
        $rutaOld = Join-Path $carpetaPadre ($nombreActual + "_old")

        try {
            Rename-Item -Path $rutaUNC -NewName ($nombreActual + "_old")
            $result.Resultado += " | ✔ Renombrada a: $($nombreActual + "_old")"
            Write-Host "✅ Carpeta renombrada: $nombreActual → $($nombreActual + "_old")"

            # 3) Forzar eliminación
            try {
                $eliminacionExitosa = Forzar-EliminarCarpeta -PathUNC $rutaOld
                if ($eliminacionExitosa) {
                    $result.Resultado += " | ✔ Carpeta _old eliminada."
                    Write-Host "✅ Carpeta eliminada exitosamente: $Usuario"
                } else {
                    $result.Resultado += " | ❌ No se pudo eliminar completamente."
                    $result.DetallesError += "La carpeta no se pudo eliminar con ningún método. "
                    $result.Error = $true
                    Write-Warning "❌ No se pudo eliminar la carpeta del perfil: $Usuario"
                }
            }
            catch {
                $result.Resultado += " | ❌ Error al forzar eliminación: $_"
                $result.DetallesError += "Error durante la eliminación forzada: $_ "
                $result.Error = $true
                Write-Warning "❌ Error al forzar eliminación del perfil: $Usuario - $_"
            }
        } catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -like "*Access denied*" -or $errorMsg -like "*Access is denied*") {
                $result.Resultado += " | ❌ Error al renombrar (permisos insuficientes)"
                $result.DetallesError += "No hay permisos para renombrar la carpeta. Ejecuta como Administrador. "
            }
            elseif ($errorMsg -like "*being used*" -or $errorMsg -like "*in use*") {
                $result.Resultado += " | ❌ Error al renombrar (archivos en uso)"
                $result.DetallesError += "La carpeta está siendo usada por otro proceso. "
            }
            else {
                $result.Resultado += " | ❌ Error al renombrar: $_"
                $result.DetallesError += "Error al renombrar: $_ "
            }
            $result.Error = $true
            Write-Warning "❌ Error al renombrar carpeta del perfil: $Usuario - $_"
        }
    }
    else {
        $result.Resultado += " | ⚠ Carpeta no encontrada."
        $result.DetallesError += "La carpeta del perfil no existe. "
        Write-Warning "⚠ Carpeta del perfil no encontrada: $Usuario"
    }

    if ($resultadoRegistro -like "*Error*" -or $result.Resultado -like "*❌*") {
        $result.Error = $true
    }

    # Mostrar resumen final
    if ($result.Error) {
        Write-Host "❌ Perfil NO eliminado completamente: $Usuario" -ForegroundColor Red
        if ($result.DetallesError) {
            Write-Host "   Detalles: $($result.DetallesError)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "✅ Perfil eliminado exitosamente: $Usuario" -ForegroundColor Green
    }

    return $result
}

#endregion

#region BLOQUE - ELIMINAR PERFILES MARCADOS

function Eliminar-PerfilesMarcados {
    param (
        [string]$Equipo,
        [System.Windows.Forms.ListView]$Lista
    )

    # Crear una lista de perfiles a eliminar
    $perfilesAEliminar = @()
    foreach ($item in $Lista.CheckedItems) {
        $estado = $item.SubItems[3].Text
        if ($estado -like "Eliminable*") {
            $perfilesAEliminar += [PSCustomObject]@{
                Usuario = $item.SubItems[0].Text
                SID     = $item.SubItems[4].Text
                Ruta    = "C:\Users\$($item.SubItems[0].Text)"
            }
        }
    }

    if ($perfilesAEliminar.Count -eq 0) {
        return "No hay perfiles válidos seleccionados para eliminar."
    }

    # Definir el tamaño del bloque (reducido para mejor responsividad)
    $batchSize = 3
    $jobs = @()

    # Mostrar progreso
    $progressForm = New-Object System.Windows.Forms.Form
    $progressForm.Text = "Eliminando perfiles..."
    $progressForm.Size = New-Object System.Drawing.Size(400, 150)
    $progressForm.StartPosition = "CenterScreen"
    $progressForm.FormBorderStyle = "FixedDialog"
    $progressForm.ControlBox = $false
    
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, 20)
    $progressBar.Size = New-Object System.Drawing.Size(350, 30)
    $progressBar.Minimum = 0
    $progressBar.Maximum = $perfilesAEliminar.Count
    $progressBar.Value = 0
    
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(20, 60)
    $statusLabel.Size = New-Object System.Drawing.Size(350, 40)
    $statusLabel.Text = "Iniciando eliminación..."
    
    $progressForm.Controls.AddRange(@($progressBar, $statusLabel))
    $progressForm.Show()
    [System.Windows.Forms.Application]::DoEvents()

    # Procesar los perfiles en bloques usando jobs paralelos
    for ($i = 0; $i -lt $perfilesAEliminar.Count; $i += $batchSize) {
        $endIndex = [Math]::Min($i + $batchSize - 1, $perfilesAEliminar.Count - 1)
        $batch = $perfilesAEliminar[$i..$endIndex]

        $job = Start-Job -ScriptBlock {
            param($batchInterno, $EquipoInterno)
            
            # Incluir las funciones necesarias en el scriptblock
            function Remove-ClaveRegistro {
                param ($Equipo, $SID)
                try {
                    $clave = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Equipo)
                    if ($reg.OpenSubKey($clave)) {
                        $reg.DeleteSubKeyTree($clave)
                    }
                    $reg.Close()
                    return "✔ Clave de registro eliminada."
                } catch {
                    return "❌ Error al eliminar clave de registro: $_"
                }
            }

            function Forzar-EliminarCarpeta {
                param([string]$PathUNC)
                
                if (-not (Test-Path $PathUNC)) {
                    return "✅ La carpeta ya no existe."
                }

                # Obtener tamaño para ajustar estrategia
                try {
                    $tamanoTotal = (Get-ChildItem -Path $PathUNC -Recurse -ErrorAction SilentlyContinue | 
                                   Measure-Object -Property Length -Sum).Sum
                    $tamanoGB = [Math]::Round($tamanoTotal / 1GB, 2)
                }
                catch {
                    $tamanoGB = 0
                }

                # Para perfiles grandes, limpiar archivos problemáticos primero
                if ($tamanoGB -gt 2) {
                    $carpetasProblematicas = @(
                        "AppData\Local\Temp",
                        "AppData\Local\Microsoft\Windows\INetCache",
                        "AppData\Local\Google\Chrome\User Data\Default\Cache",
                        "AppData\Local\Microsoft\Edge\User Data\Default\Cache"
                    )

                    foreach ($subcarpeta in $carpetasProblematicas) {
                        $rutaSubcarpeta = Join-Path $PathUNC $subcarpeta
                        if (Test-Path $rutaSubcarpeta) {
                            try {
                                Get-ChildItem -Path $rutaSubcarpeta -Recurse -File -ErrorAction SilentlyContinue | 
                                ForEach-Object {
                                    try {
                                        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                                    }
                                    catch { }
                                }
                            }
                            catch { }
                        }
                    }
                }

                # Intento 1: PowerShell (más rápido)
                try {
                    Remove-Item -Path $PathUNC -Recurse -Force -ErrorAction Stop
                    return "✅ Carpeta eliminada con Remove-Item ($tamanoGB GB)."
                } catch { }

                # Intento 2: ROBOCOPY (muy efectivo para carpetas grandes)
                try {
                    $tempEmpty = Join-Path $env:TEMP "EmptyFolder_$(Get-Random)"
                    New-Item -Path $tempEmpty -ItemType Directory -Force | Out-Null
                    
                    robocopy $tempEmpty $PathUNC /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
                    Remove-Item -Path $tempEmpty -Force -ErrorAction SilentlyContinue
                    
                    if (-not (Test-Path $PathUNC) -or (Get-ChildItem -Path $PathUNC -ErrorAction SilentlyContinue).Count -eq 0) {
                        Remove-Item -Path $PathUNC -Force -ErrorAction SilentlyContinue
                        return "✅ Carpeta eliminada con ROBOCOPY ($tamanoGB GB)."
                    }
                } catch { }

                # Intento 3: CMD (último recurso)
                try {
                    $escaped = $PathUNC -replace '"', '""'
                    $cmd = "rd /s /q `"$escaped`""
                    cmd.exe /c $cmd | Out-Null

                    if (-not (Test-Path $PathUNC)) {
                        return "✅ Carpeta eliminada con CMD ($tamanoGB GB)."
                    }
                } catch { }

                # Si todo falla, registrar para reinicio
                try {
                    $equipo = ($PathUNC -split "\\")[2]
                    $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"
                    
                    $clave = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $equipo)
                    $sessionKey = $clave.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager", $true)
                    
                    if ($sessionKey) {
                        $pendientes = $sessionKey.GetValue("PendingFileRenameOperations", @())
                        $nuevoValor = $pendientes + @($rutaLocal, "")
                        $sessionKey.SetValue("PendingFileRenameOperations", $nuevoValor, [Microsoft.Win32.RegistryValueKind]::MultiString)
                        $sessionKey.Close()
                    }
                    $clave.Close()
                    
                    return "🕒 Registrada para eliminación tras reinicio ($tamanoGB GB). REQUIERE REINICIO."
                } catch {
                    return "❌ No se pudo eliminar ($tamanoGB GB). Error: $_"
                }
            }

            function Eliminar-PerfilCompleto {
                param (
                    [string]$Equipo,
                    [string]$RutaPerfil,
                    [string]$SID,
                    [string]$Usuario
                )

                $result = [PSCustomObject]@{
                    Usuario  = $Usuario
                    SID      = $SID
                    Resultado = ""
                    Error     = $false
                }

                # 1) Eliminar clave en ProfileList
                $resultadoRegistro = Remove-ClaveRegistro -Equipo $Equipo -SID $SID
                $result.Resultado += $resultadoRegistro

                # 2) Renombrar la carpeta a _old
                $rutaUNC = $RutaPerfil -replace "^[a-zA-Z]:", "\\$Equipo\C$"
                if (Test-Path $rutaUNC) {
                    $nombreActual = Split-Path $rutaUNC -Leaf
                    $carpetaPadre = Split-Path $rutaUNC -Parent
                    $rutaOld = Join-Path $carpetaPadre ($nombreActual + "_old")

                    try {
                        Rename-Item -Path $rutaUNC -NewName ($nombreActual + "_old")
                        $result.Resultado += " | ✔ Renombrada a: $($nombreActual + "_old")"

                        # 3) Forzar eliminación
                        try {
                            Forzar-EliminarCarpeta -PathUNC $rutaOld
                            $result.Resultado += " | ✔ Carpeta _old eliminada."
                        }
                        catch {
                            $result.Resultado += " | ❌ Error al forzar eliminación: $_"
                            $result.Error = $true
                        }
                    } catch {
                        $result.Resultado += " | ❌ Error al renombrar la carpeta: $_"
                        $result.Error = $true
                    }
                }
                else {
                    $result.Resultado += " | ⚠ Carpeta no encontrada."
                }

                if ($resultadoRegistro -like "*Error*" -or $result.Resultado -like "*❌*") {
                    $result.Error = $true
                }

                return $result
            }
            
            $resultadosLocal = @()
            foreach ($p in $batchInterno) {
                # Llamada a la función que elimina el perfil completo
                $resultado = Eliminar-PerfilCompleto -Equipo $EquipoInterno -RutaPerfil $p.Ruta -SID $p.SID -Usuario $p.Usuario
                $resultadosLocal += $resultado
            }
            return $resultadosLocal
        } -ArgumentList $batch, $Equipo

        $jobs += $job
        
        # Actualizar progreso
        $statusLabel.Text = "Procesando perfiles... ($($i + $batch.Count)/$($perfilesAEliminar.Count))"
        $progressBar.Value = [Math]::Min($i + $batch.Count, $perfilesAEliminar.Count)
        [System.Windows.Forms.Application]::DoEvents()
    }

    # Esperar y procesar jobs de manera más eficiente
    $statusLabel.Text = "Procesando resultados..."
    $progressBar.Style = "Blocks"
    $progressBar.Value = 0
    $progressBar.Maximum = $perfilesAEliminar.Count

    # Procesar jobs individualmente para mejor responsividad
    $todosResultados = @()
    $procesados = 0
    $jobsConTimeout = 0
    $jobsExitosos = 0

    foreach ($job in $jobs) {
        # Mostrar progreso del job actual
        $statusLabel.Text = "Procesando job $($procesados + 1)/$($jobs.Count)..."
        [System.Windows.Forms.Application]::DoEvents()

        # Determinar timeout basado en el tamaño del perfil
        $tamanoPerfil = 0
        try {
            $rutaPerfil = "\\$Equipo\C$\Users\$($perfilOriginal.Usuario)"
            if (Test-Path $rutaPerfil) {
                $tamanoPerfil = (Get-ChildItem -Path $rutaPerfil -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                $tamanoPerfil = [Math]::Round($tamanoPerfil / 1MB, 2)  # En MB
            }
        } catch {
            $tamanoPerfil = 0
        }

        # Timeout adaptativo basado en tamaño
        if ($tamanoPerfil -lt 50) {
            $timeout = 60   # 1 minuto para perfiles pequeños
        } elseif ($tamanoPerfil -lt 500) {
            $timeout = 90   # 1.5 minutos para perfiles medianos
        } else {
            $timeout = 120  # 2 minutos para perfiles grandes
        }

        $espera = 0
        $perfilYaEliminado = $false

        while ($job.State -eq "Running" -and $espera -lt $timeout) {
            Start-Sleep -Milliseconds 3000  # Verificar cada 3 segundos
            $espera += 3

            # Verificar si el perfil ya fue eliminado mientras esperamos
            if ($espera -ge 10) {  # Después de 10 segundos, empezar a verificar
                try {
                    $estadoActual = Verificar-EliminacionPerfil -Usuario $perfilOriginal.Usuario -SID $perfilOriginal.SID -Equipo $Equipo
                    if ($estadoActual.EstadoGeneral -ne "Sin eliminar" -and $estadoActual.EstadoGeneral -notlike "*intacta*") {
                        $perfilYaEliminado = $true
                        $statusLabel.Text = "Perfil eliminado, esperando confirmación del job... ($($espera)s)"
                        break  # Salir del bucle, el perfil ya fue procesado
                    }
                } catch {
                    # Ignorar errores de verificación durante la espera
                }
            }

            # Actualizar mensaje cada 15 segundos
            if ($espera % 15 -eq 0) {
                if ($perfilYaEliminado) {
                    $statusLabel.Text = "Perfil procesado, finalizando job... ($($espera)s)"
                } else {
                    $statusLabel.Text = "Procesando job $($procesados + 1)... ($($espera)s/${timeout}s, ~${tamanoPerfil}MB)"
                }
                [System.Windows.Forms.Application]::DoEvents()
            }
        }

        # Si el job terminó, procesar su resultado
        if ($job.State -eq "Completed") {
            try {
                $resultadoJob = Receive-Job -Job $job -ErrorAction Stop
                if ($resultadoJob) {
                    # Los jobs devuelven arrays, procesarlos correctamente
                    if ($resultadoJob -is [array]) {
                        foreach ($resultado in $resultadoJob) {
                            if ($resultado) {
                                $todosResultados += $resultado
                            }
                        }
                    } else {
                        $todosResultados += $resultadoJob
                    }
                    $jobsExitosos++
                }
            } catch {
                # Si hay error al recibir el job, pero el perfil ya fue eliminado, considerarlo exitoso
                if ($perfilYaEliminado) {
                    $resultadoExito = [PSCustomObject]@{
                        Usuario = $perfilOriginal.Usuario
                        SID = $perfilOriginal.SID
                        Resultado = "✅ Eliminación completada (job finalizó correctamente)"
                        Error = $false
                    }
                    $todosResultados += $resultadoExito
                    $jobsExitosos++
                } else {
                    # Si no fue eliminado, reportar el error
                    $errorResultado = [PSCustomObject]@{
                        Usuario = $perfilOriginal.Usuario
                        SID = $perfilOriginal.SID
                        Resultado = "❌ Error al procesar resultado del job: $_"
                        Error = $true
                    }
                    $todosResultados += $errorResultado
                }
            }
        } elseif ($job.State -eq "Running") {
            # Job timeout - pero verificar si el trabajo se completó
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            $jobsConTimeout++

            # Intentar recibir resultados parciales
            try {
                $resultadoParcial = Receive-Job -Job $job -ErrorAction SilentlyContinue
                if ($resultadoParcial) {
                    if ($resultadoParcial -is [array]) {
                        foreach ($resultado in $resultadoParcial) {
                            if ($resultado) {
                                $todosResultados += $resultado
                            }
                        }
                    } else {
                        $todosResultados += $resultadoParcial
                    }
                } elseif ($perfilYaEliminado) {
                    # Si no hay resultados pero el perfil fue eliminado, crear resultado exitoso
                    $resultadoExito = [PSCustomObject]@{
                        Usuario = $perfilOriginal.Usuario
                        SID = $perfilOriginal.SID
                        Resultado = "✅ Eliminación completada (a pesar del timeout del job)"
                        Error = $false
                    }
                    $todosResultados += $resultadoExito
                } else {
                    # Si no hay resultados y el perfil no fue eliminado, reportar timeout
                    $errorResultado = [PSCustomObject]@{
                        Usuario = $perfilOriginal.Usuario
                        SID = $perfilOriginal.SID
                        Resultado = "❌ Job timeout - detenido después de $timeout segundos (~${tamanoPerfil}MB)"
                        Error = $true
                    }
                    $todosResultados += $errorResultado
                }
            } catch {
                if ($perfilYaEliminado) {
                    $resultadoExito = [PSCustomObject]@{
                        Usuario = $perfilOriginal.Usuario
                        SID = $perfilOriginal.SID
                        Resultado = "✅ Eliminación completada (job detuvo pero trabajo finalizado)"
                        Error = $false
                    }
                    $todosResultados += $resultadoExito
                } else {
                    $errorResultado = [PSCustomObject]@{
                        Usuario = $perfilOriginal.Usuario
                        SID = $perfilOriginal.SID
                        Resultado = "❌ Job timeout - detenido después de $timeout segundos (~${tamanoPerfil}MB)"
                        Error = $true
                    }
                    $todosResultados += $errorResultado
                }
            }
        } else {
            # Job falló
            $errorResultado = [PSCustomObject]@{
                Usuario = $perfilOriginal.Usuario
                SID = $perfilOriginal.SID
                Resultado = "❌ Job falló: $($job.State)"
                Error = $true
            }
            $todosResultados += $errorResultado
        }

        # Limpiar job inmediatamente
        Remove-Job -Job $job -ErrorAction SilentlyContinue

        # Actualizar progreso
        $procesados++
        $progressBar.Value = $procesados
        $statusLabel.Text = "Jobs procesados: $procesados/$($jobs.Count) | Exitosos: $jobsExitosos | Timeouts: $jobsConTimeout"
        [System.Windows.Forms.Application]::DoEvents()
    }

    # Aplanar resultados (los jobs devuelven arrays) y mapear con perfiles originales
    $resultadosPlanos = @()
    $mapeoResultados = @{}  # Para mapear resultados con perfiles originales

    # Crear mapeo inicial de perfiles a procesar
    for ($i = 0; $i -lt $perfilesAEliminar.Count; $i++) {
        $perfil = $perfilesAEliminar[$i]
        $mapeoResultados[$perfil.Usuario] = @{
            PerfilOriginal = $perfil
            ResultadoJob = $null
            EstadoFinal = $null
        }
    }

    # Procesar resultados de jobs y mapearlos
    foreach ($resultado in $todosResultados) {
        if ($resultado -is [array]) {
            foreach ($item in $resultado) {
                if ($item -and $item.Usuario) {
                    # Si el resultado tiene un usuario válido, mapearlo
                    if ($mapeoResultados.ContainsKey($item.Usuario)) {
                        $mapeoResultados[$item.Usuario].ResultadoJob = $item
                    }
                    $resultadosPlanos += $item
                }
            }
        } else {
            if ($resultado -and $resultado.Usuario) {
                # Si el resultado tiene un usuario válido, mapearlo
                if ($mapeoResultados.ContainsKey($resultado.Usuario)) {
                    $mapeoResultados[$resultado.Usuario].ResultadoJob = $resultado
                }
                $resultadosPlanos += $resultado
            }
        }
    }

    # Para resultados sin usuario válido (timeouts, errores), intentar mapear por posición
    $resultadosSinUsuario = $resultadosPlanos | Where-Object { -not $_.Usuario -or $_.Usuario -like "Job *"}
    if ($resultadosSinUsuario) {
        $usuariosSinResultado = $mapeoResultados.Keys | Where-Object { -not $mapeoResultados[$_].ResultadoJob }
        $i = 0
        foreach ($usuario in $usuariosSinResultado) {
            if ($i -lt $resultadosSinUsuario.Count) {
                # Crear un resultado corregido para este usuario
                $resultadoCorregido = $resultadosSinUsuario[$i] | Select-Object *
                $resultadoCorregido.Usuario = $usuario
                $resultadoCorregido.SID = $mapeoResultados[$usuario].PerfilOriginal.SID
                $mapeoResultados[$usuario].ResultadoJob = $resultadoCorregido
                $i++
            }
        }
    }

    # Procesar resultados con progreso usando el mapeo mejorado
    $statusLabel.Text = "Analizando resultados..."
    $progressBar.Value = 0
    $progressBar.Maximum = $perfilesAEliminar.Count

    # Separar perfiles eliminados y con error
    $eliminados = @()
    $errores = @()
    $solucionesRecomendadas = @()
    $estadosFinales = @()
    $procesados = 0

    foreach ($usuario in $mapeoResultados.Keys) {
        $mapeo = $mapeoResultados[$usuario]
        $res = $mapeo.ResultadoJob
        $perfilOriginal = $mapeo.PerfilOriginal

        # Verificar estado final del perfil usando SID del perfil original
        try {
            $estadoFinal = Verificar-EliminacionPerfil -Usuario $usuario -SID $perfilOriginal.SID -Equipo $Equipo
            $estadosFinales += $estadoFinal
        } catch {
            $estadoFinal = [PSCustomObject]@{
                Usuario = $usuario
                EstadoGeneral = "Error al verificar"
                Detalles = $_
            }
            $estadosFinales += $estadoFinal
        }

        # Si no hay resultado del job, crear uno basado en la verificación del estado
        if (-not $res) {
            if ($estadoFinal.EstadoGeneral -eq "Completamente Eliminado" -or
                $estadoFinal.EstadoGeneral -like "*pendiente eliminación*" -or
                $estadoFinal.EstadoGeneral -like "*_old*") {
                $res = [PSCustomObject]@{
                    Usuario = $usuario
                    SID = $perfilOriginal.SID
                    Resultado = "✅ Proceso de eliminación iniciado correctamente - $($estadoFinal.EstadoGeneral)"
                    Error = $false
                }
            } else {
                $res = [PSCustomObject]@{
                    Usuario = $usuario
                    SID = $perfilOriginal.SID
                    Resultado = "❌ Sin información del job - Estado: $($estadoFinal.EstadoGeneral)"
                    Error = $true
                }
            }
        }

        # Procesar el resultado - considerar más estados como exitosos
        $esExitoso = $false
        if ($res.Error -eq $false) {
            $esExitoso = $true
        } elseif ($estadoFinal.EstadoGeneral -eq "Completamente Eliminado" -or
                  $estadoFinal.EstadoGeneral -like "*pendiente eliminación*" -or
                  $estadoFinal.EstadoGeneral -like "*_old*") {
            # Si el job reportó error pero el estado final muestra eliminación, considerarlo exitoso
            $esExitoso = $true
            $res.Error = $false
            $res.Resultado = "✅ Eliminación exitosa verificada - $($estadoFinal.EstadoGeneral)"
        }

        if (-not $esExitoso) {
            $errores += "$($res.Usuario) => $($res.Resultado) [Estado: $($estadoFinal.EstadoGeneral)]"
            # Obtener soluciones específicas para este error
            try {
                $soluciones = Get-SolucionesError -TipoError $res.Resultado -Usuario $res.Usuario -Equipo $Equipo
                $solucionesRecomendadas += "Para $($res.Usuario) [Estado: $($estadoFinal.EstadoGeneral)]:"
                $solucionesRecomendadas += $soluciones
                $solucionesRecomendadas += ""
            } catch {
                $solucionesRecomendadas += "Para $($res.Usuario): Error al obtener soluciones específicas"
            }
        } else {
            $eliminados += "$($res.Usuario) => $($res.Resultado) [Estado: $($estadoFinal.EstadoGeneral)]"
        }

        # Actualizar progreso
        $procesados++
        $progressBar.Value = $procesados
        $statusLabel.Text = "Analizando... ($procesados/$($perfilesAEliminar.Count))"
        [System.Windows.Forms.Application]::DoEvents()
    }

    # Completar progreso y cerrar ventana
    $statusLabel.Text = "Completando..."
    $progressBar.Value = $progressBar.Maximum
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 800  # Pausa para mostrar completado

    $progressForm.Close()
    $progressForm.Dispose()

    # Crear resumen completo y bien estructurado
    $resumen = "═══════════════════════════════════════════════════════════════`n"
    $resumen += "               GHOSTHUNTER - RESULTADO DE ELIMINACIÓN`n"
    $resumen += "═══════════════════════════════════════════════════════════════`n`n"

    # SECCIÓN 1: RESULTADOS PRINCIPALES
    $resumen += "📋 RESULTADOS PRINCIPALES`n"
    $resumen += "───────────────────────────────────────────────────────────────`n"

    if ($eliminados.Count -gt 0) {
        $resumen += "✅ PERFILES ELIMINADOS EXITOSAMENTE ($($eliminados.Count)):`n"
        foreach ($eliminado in $eliminados) {
            $resumen += "   $eliminado`n"
        }
    }

    if ($errores.Count -gt 0) {
        if ($eliminados.Count -gt 0) { $resumen += "`n" }
        $resumen += "❌ ERRORES ENCONTRADOS ($($errores.Count)):`n"
        foreach ($entrada in $errores) {
            $resumen += "   $entrada`n"
        }
    }

    if ($eliminados.Count -eq 0 -and $errores.Count -eq 0) {
        $resumen += "⚠️  No se procesaron perfiles.`n"
    }

    # SECCIÓN 2: ESTADÍSTICAS DE PROCESAMIENTO
    $resumen += "`n`n📊 ESTADÍSTICAS DE PROCESAMIENTO`n"
    $resumen += "───────────────────────────────────────────────────────────────`n"
    $resumen += "Perfiles procesados: $($perfilesAEliminar.Count)`n"
    $resumen += "Jobs creados: $($jobs.Count)`n"
    $resumen += "Jobs exitosos: $jobsExitosos`n"
    if ($jobsConTimeout -gt 0) {
        $resumen += "Jobs con timeout: $jobsConTimeout ⚠️`n"
    }

    # SECCIÓN 3: ESTADOS FINALES DETALLADOS
    $resumen += "`n`n🔍 ESTADOS FINALES VERIFICADOS`n"
    $resumen += "───────────────────────────────────────────────────────────────`n"

    if ($completamenteEliminados -gt 0) {
        $resumen += "✅ Completamente eliminados: $completamenteEliminados`n"
    }
    if ($renombradosOld -gt 0) {
        $resumen += "📁 Renombrados (_old): $renombradosOld`n"
    }
    if ($parcialmenteEliminados -gt 0) {
        $resumen += "⚠️  Parcialmente eliminados: $parcialmenteEliminados`n"
    }
    if ($sinEliminar -gt 0) {
        $resumen += "❌ Sin eliminar: $sinEliminar`n"
    }
    if ($erroresVerificacion -gt 0) {
        $resumen += "🔍 Errores de verificación: $erroresVerificacion`n"
    }

    # SECCIÓN 4: TIMEOUTS ADAPTATIVOS (solo si aplica)
    if ($jobsConTimeout -gt 0) {
        $resumen += "`n`n⏱️  TIMEOUTS ADAPTATIVOS`n"
        $resumen += "───────────────────────────────────────────────────────────────`n"
        $resumen += "• Timeout basado en tamaño del perfil:`n"
        $resumen += "  - Pequeños (<50MB): 1 minuto`n"
        $resumen += "  - Medianos (<500MB): 1.5 minutos`n"
        $resumen += "  - Grandes (≥500MB): 2 minutos`n"
        $resumen += "• Verificación inteligente del estado real`n"
        $resumen += "• Los timeouts no siempre indican fallos`n"
    }

    # SECCIÓN 5: RECOMENDACIONES ESPECÍFICAS
    $tieneRecomendaciones = $false
    $recomendaciones = "`n`n💡 RECOMENDACIONES`n"
    $recomendaciones += "───────────────────────────────────────────────────────────────`n"

    if ($renombradosOld -gt 0) {
        $recomendaciones += "• Perfiles _old: Se eliminarán automáticamente al reiniciar`n"
        $tieneRecomendaciones = $true
    }

    if ($errores.Count -gt 0) {
        $recomendaciones += "• Para errores: Verificar permisos y procesos en ejecución`n"
        $recomendaciones += "• Considerar reinicio del sistema para eliminación completa`n"
        $tieneRecomendaciones = $true
    }

    if ($parcialmenteEliminados -gt 0) {
        $recomendaciones += "• Eliminaciones parciales: Revisar manualmente los archivos restantes`n"
        $tieneRecomendaciones = $true
    }

    if ($tieneRecomendaciones) {
        $resumen += $recomendaciones
    }

    # SECCIÓN 6: SOLUCIONES DETALLADAS (solo si hay errores)
    if ($solucionesRecomendadas.Count -gt 0) {
        $resumen += "`n`n🔧 SOLUCIONES DETALLADAS`n"
        $resumen += "───────────────────────────────────────────────────────────────`n"
        foreach ($solucion in $solucionesRecomendadas) {
            $resumen += "$solucion`n"
        }
    }

    # PIE DEL RESUMEN
    $resumen += "`n═══════════════════════════════════════════════════════════════`n"
    $resumen += "Proceso completado - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
    $resumen += "═══════════════════════════════════════════════════════════════"

    # Mostrar resumen en ventana prominente
    Mostrar-ResumenProminente -Resumen $resumen -Errores $errores.Count -Exitosos $eliminados.Count

    return $resumen
}

#endregion

#region BLOQUE - EXPORTAR RESULTADOS

function Exportar-PerfilesCSV {
    param (
        [System.Windows.Forms.ListView]$Lista,
        [string]$Equipo
    )

    $export = @()
    foreach ($item in $Lista.Items) {
        $export += [PSCustomObject]@{
            Usuario   = $item.SubItems[0].Text
            UltimoLogon = $item.SubItems[1].Text
            Tamano    = $item.SubItems[2].Text
            Estado    = $item.SubItems[3].Text
            SID       = $item.SubItems[4].Text
            Equipo    = $Equipo
            Exportado = (Get-Date).ToString("yyyy-MM-dd HH:mm")
        }
    }
    if ($export.Count -eq 0) {
        return "No hay perfiles para exportar."
    }

    $path = [System.IO.Path]::Combine(
        [Environment]::GetFolderPath("Desktop"),
        "Perfiles_$Equipo_" + (Get-Date -Format "yyyyMMdd_HHmm") + ".csv"
    )

    try {
        $export | Export-Csv -Path $path -Encoding UTF8 -NoTypeInformation
        return "Exportado correctamente a:`n$path"
    } catch {
        return "❌ Error al exportar: $_"
    }
}

#endregion

#region BLOQUE - FILTRO DINÁMICO DE CHECKBOXES

$global:PerfilesCargados = @()

function Refrescar-ListViewFiltrado {
    param (
        [System.Collections.ObjectModel.Collection[object]]$Datos,
        [bool]$FiltrarAntiguos,
        [bool]$FiltrarPequenos
    )

    $listView.Items.Clear()

    # Nueva lógica: todos los perfiles eliminables son candidatos a eliminación
    if (-not $FiltrarAntiguos -and -not $FiltrarPequenos) {
        $filtrados = $Datos
    }
    elseif ($FiltrarAntiguos -and $FiltrarPequenos) {
        # Mostrar solo los eliminables
        $filtrados = $Datos | Where-Object {
            $_.Estado -like "Eliminable*"
        }
    }
    elseif ($FiltrarAntiguos) {
        # Mostrar perfiles antiguos (incluye eliminables por tiempo)
        $filtrados = $Datos | Where-Object { 
            $_.Estado -like "*días sin uso*" 
        }
    }
    else {
        # Mostrar perfiles pequeños (incluye eliminables por tamaño)
        $filtrados = $Datos | Where-Object { 
            $_.Estado -like "*< 1GB*" 
        }
    }

    foreach ($perfil in $filtrados) {
        $item = New-Object System.Windows.Forms.ListViewItem($perfil.Usuario)
        $item.SubItems.Add($perfil.UltimoLogon.ToString("yyyy-MM-dd HH:mm"))
        $item.SubItems.Add((Format-TamanoArchivo -Bytes $perfil.TamanoBytes))
        $item.SubItems.Add($perfil.Estado)
        $item.SubItems.Add($perfil.SID)

        switch -Wildcard ($perfil.Estado) {
            "Protegido*" {
                $item.ForeColor = [System.Drawing.Color]::Blue
            }
            "Activo*" {
                $item.ForeColor = [System.Drawing.Color]::Green
            }
            "Eliminable*" {
                $item.ForeColor = [System.Drawing.Color]::Red
                # Marcar automáticamente todos los eliminables
                $item.Checked = $true
            }
        }

        [void]$listView.Items.Add($item)
    }
}

#endregion

#region BLOQUE - GENERAR INFORME DETALLADO

function Generar-InformeTXT {
    param (
        [System.Collections.ObjectModel.Collection[object]]$Datos,
        [string]$Equipo
    )

    if ($Datos.Count -eq 0) {
        return "No hay datos para generar informe."
    }

    $ahora = Get-Date
    $ruta = [System.IO.Path]::Combine(
        [Environment]::GetFolderPath("Desktop"),
        "Informe_GhostHunter_$Equipo_" + $ahora.ToString("yyyyMMdd_HHmm") + ".txt"
    )

    $activos     = $Datos | Where-Object { $_.Estado -like "Activo*" }
    $eliminables = $Datos | Where-Object { $_.Estado -like "Eliminable*" }

    $lineas = @()
    $lineas += "===== Informe de Perfiles - GhostHunter ====="
    $lineas += "Equipo analizado : $Equipo"
    $lineas += "Fecha/Hora       : $($ahora.ToString("yyyy-MM-dd HH:mm"))"
    $lineas += ""
    $lineas += "Total perfiles encontrados : $($Datos.Count)"
    $lineas += "  - Activos     : $($activos.Count) (> 1GB y usados en últimos 3 meses)"
    $lineas += "  - Eliminables : $($eliminables.Count) (< 1GB o > 3 meses sin uso)"
    $lineas += ""
    $lineas += "----- Detalle por perfil -----"

    foreach ($p in $Datos) {
        $lineas += ""
        $lineas += "Usuario    : $($p.Usuario)"
        $lineas += "Últ. Logon: $($p.UltimoLogon.ToString("yyyy-MM-dd HH:mm"))"
        $lineas += "Tamaño     : $(Format-TamanoArchivo -Bytes $p.TamanoBytes)"
        $lineas += "Estado     : $($p.Estado)"
        $lineas += "SID        : $($p.SID)"
    }

    try {
        $lineas | Out-File -FilePath $ruta -Encoding UTF8
        return "Informe generado correctamente en:`n$ruta"
    } catch {
        return "❌ Error al generar informe: $_"
    }
}

#endregion

#region FUNCIONES DE UI

function Mostrar-ResumenProminente {
    param (
        [string]$Resumen,
        [int]$Errores,
        [int]$Exitosos
    )

    # Crear ventana de resumen prominente más grande para el nuevo formato
    $resumenForm = New-Object System.Windows.Forms.Form
    $resumenForm.Text = "GhostHunter - Resumen de Eliminación"
    $resumenForm.Size = New-Object System.Drawing.Size(900, 700)  # Más grande
    $resumenForm.StartPosition = "CenterScreen"
    $resumenForm.BackColor = [System.Drawing.Color]::White
    $resumenForm.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $resumenForm.Topmost = $true  # Ventana siempre en primer plano
    $resumenForm.ShowInTaskbar = $true
    $resumenForm.MinimizeBox = $false
    $resumenForm.MaximizeBox = $true  # Permitir maximizar
    $resumenForm.FormBorderStyle = "Sizable"  # Permitir redimensionar

    # Icono según resultado
    if ($Errores -eq 0 -and $Exitosos -gt 0) {
        $resumenForm.Icon = [System.Drawing.SystemIcons]::Information
    } elseif ($Errores -gt 0 -and $Exitosos -eq 0) {
        $resumenForm.Icon = [System.Drawing.SystemIcons]::Error
    } else {
        $resumenForm.Icon = [System.Drawing.SystemIcons]::Warning
    }

    # Título principal con mejor formato
    $lblTitulo = New-Object System.Windows.Forms.Label
    $lblTitulo.Text = "GHOSTHUNTER - RESULTADO DE ELIMINACIÓN"
    $lblTitulo.Location = New-Object System.Drawing.Point(20, 20)
    $lblTitulo.Size = New-Object System.Drawing.Size(850, 35)
    $lblTitulo.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblTitulo.TextAlign = "MiddleCenter"
    $lblTitulo.BackColor = [System.Drawing.Color]::FromArgb(240, 248, 255)
    $lblTitulo.BorderStyle = "FixedSingle"

    # Subtítulo con estado
    $lblSubtitulo = New-Object System.Windows.Forms.Label
    $lblSubtitulo.Location = New-Object System.Drawing.Point(20, 65)
    $lblSubtitulo.Size = New-Object System.Drawing.Size(850, 25)
    $lblSubtitulo.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lblSubtitulo.TextAlign = "MiddleCenter"

    if ($Errores -eq 0 -and $Exitosos -gt 0) {
        $lblSubtitulo.ForeColor = [System.Drawing.Color]::Green
        $lblSubtitulo.Text = "✅ PROCESO COMPLETADO EXITOSAMENTE"
        $lblTitulo.BackColor = [System.Drawing.Color]::FromArgb(240, 255, 240)
    } elseif ($Errores -gt 0 -and $Exitosos -eq 0) {
        $lblSubtitulo.ForeColor = [System.Drawing.Color]::Red
        $lblSubtitulo.Text = "❌ PROCESO COMPLETADO CON ERRORES"
        $lblTitulo.BackColor = [System.Drawing.Color]::FromArgb(255, 240, 240)
    } elseif ($Errores -gt 0 -and $Exitosos -gt 0) {
        $lblSubtitulo.ForeColor = [System.Drawing.Color]::Orange
        $lblSubtitulo.Text = "⚠️ PROCESO COMPLETADO PARCIALMENTE"
        $lblTitulo.BackColor = [System.Drawing.Color]::FromArgb(255, 248, 240)
    } else {
        $lblSubtitulo.ForeColor = [System.Drawing.Color]::Gray
        $lblSubtitulo.Text = "ℹ️ PROCESO COMPLETADO"
    }

    # Caja de texto para el resumen con mejor formato
    $txtResumen = New-Object System.Windows.Forms.RichTextBox
    $txtResumen.ReadOnly = $true
    $txtResumen.Location = New-Object System.Drawing.Point(20, 100)
    $txtResumen.Size = New-Object System.Drawing.Size(850, 520)
    $txtResumen.Font = New-Object System.Drawing.Font("Consolas", 9)
    $txtResumen.BackColor = [System.Drawing.Color]::White
    $txtResumen.BorderStyle = "FixedSingle"
    $txtResumen.WordWrap = $false  # No wrap para mantener formato
    $txtResumen.ScrollBars = "Both"  # Scroll horizontal y vertical

    # Aplicar formato al texto
    $txtResumen.Text = $Resumen

    # Resaltar secciones importantes
    try {
        # Resaltar títulos de secciones
        $secciones = @("RESULTADOS PRINCIPALES", "ESTADÍSTICAS DE PROCESAMIENTO", "ESTADOS FINALES VERIFICADOS", "TIMEOUTS ADAPTATIVOS", "RECOMENDACIONES", "SOLUCIONES DETALLADAS")
        foreach ($seccion in $secciones) {
            $start = $txtResumen.Text.IndexOf($seccion)
            if ($start -ge 0) {
                $txtResumen.Select($start, $seccion.Length)
                $txtResumen.SelectionFont = New-Object System.Drawing.Font("Consolas", 9, [System.Drawing.FontStyle]::Bold)
                $txtResumen.SelectionColor = [System.Drawing.Color]::Blue
            }
        }

        # Resaltar resultados exitosos
        $exitosos = $txtResumen.Text.IndexOf("✅")
        while ($exitosos -ge 0) {
            $lineEnd = $txtResumen.Text.IndexOf("`n", $exitosos)
            if ($lineEnd -eq -1) { $lineEnd = $txtResumen.Text.Length }
            $length = $lineEnd - $exitosos
            $txtResumen.Select($exitosos, $length)
            $txtResumen.SelectionColor = [System.Drawing.Color]::Green
            $exitosos = $txtResumen.Text.IndexOf("✅", $lineEnd)
        }

        # Resaltar errores
        $errores = $txtResumen.Text.IndexOf("❌")
        while ($errores -ge 0) {
            $lineEnd = $txtResumen.Text.IndexOf("`n", $errores)
            if ($lineEnd -eq -1) { $lineEnd = $txtResumen.Text.Length }
            $length = $lineEnd - $errores
            $txtResumen.Select($errores, $length)
            $txtResumen.SelectionColor = [System.Drawing.Color]::Red
            $errores = $txtResumen.Text.IndexOf("❌", $lineEnd)
        }

        # Resaltar advertencias
        $advertencias = $txtResumen.Text.IndexOf("⚠️")
        while ($advertencias -ge 0) {
            $lineEnd = $txtResumen.Text.IndexOf("`n", $advertencias)
            if ($lineEnd -eq -1) { $lineEnd = $txtResumen.Text.Length }
            $length = $lineEnd - $advertencias
            $txtResumen.Select($advertencias, $length)
            $txtResumen.SelectionColor = [System.Drawing.Color]::Orange
            $advertencias = $txtResumen.Text.IndexOf("⚠️", $lineEnd)
        }

    } catch {
        # Si hay error en el formateo, continuar sin formato
    }

    # Botones mejorados
    $btnCerrar = New-Object System.Windows.Forms.Button
    $btnCerrar.Text = "Cerrar (ESC)"
    $btnCerrar.Location = New-Object System.Drawing.Point(375, 635)
    $btnCerrar.Size = New-Object System.Drawing.Size(120, 40)
    $btnCerrar.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnCerrar.BackColor = [System.Drawing.Color]::FromArgb(0, 123, 255)
    $btnCerrar.ForeColor = [System.Drawing.Color]::White
    $btnCerrar.FlatStyle = "Flat"

    # Botón de copiar al portapapeles
    $btnCopiar = New-Object System.Windows.Forms.Button
    $btnCopiar.Text = "Copiar al Portapapeles"
    $btnCopiar.Location = New-Object System.Drawing.Point(200, 635)
    $btnCopiar.Size = New-Object System.Drawing.Size(160, 40)
    $btnCopiar.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnCopiar.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    $btnCopiar.ForeColor = [System.Drawing.Color]::White
    $btnCopiar.FlatStyle = "Flat"

    $btnCerrar.Add_Click({
        $resumenForm.Close()
    })

    $btnCopiar.Add_Click({
        [System.Windows.Forms.Clipboard]::SetText($txtResumen.Text)
        [System.Windows.Forms.MessageBox]::Show("Resumen copiado al portapapeles.", "GhostHunter", "OK", "Information")
    })

    # Agregar controles a la ventana
    $resumenForm.Controls.AddRange(@($lblTitulo, $lblSubtitulo, $txtResumen, $btnCopiar, $btnCerrar))

    # Atajo de teclado ESC para cerrar
    $resumenForm.KeyPreview = $true
    $resumenForm.Add_KeyDown({
        if ($_.KeyCode -eq "Escape") {
            $resumenForm.Close()
        }
    })

    # Mostrar ventana de forma modal
    $resumenForm.ShowDialog() | Out-Null
    $resumenForm.Dispose()
}

#endregion

#region FUNCIONES DE LIMPIEZA DE JOBS

function Limpiar-JobsHuérfanos {
    <#
    .SYNOPSIS
        Limpia jobs huérfanos de ejecuciones anteriores de GhostHunter
    #>
    try {
        # Buscar jobs relacionados con GhostHunter
        $jobsGhostHunter = Get-Job | Where-Object {
            $_.Name -like "*GhostHunter*" -or
            $_.Command -like "*GhostHunter*" -or
            $_.Command -like "*Eliminar-Perfil*"
        }

        if ($jobsGhostHunter) {
            Write-Host "Encontrados $($jobsGhostHunter.Count) jobs huérfanos de GhostHunter. Limpiando..."
            $jobsGhostHunter | Stop-Job -ErrorAction SilentlyContinue
            $jobsGhostHunter | Remove-Job -ErrorAction SilentlyContinue

            # Mostrar mensaje al usuario
            [System.Windows.Forms.MessageBox]::Show(
                "Se encontraron y limpiaron $($jobsGhostHunter.Count) jobs pendientes de ejecuciones anteriores.`n`nEsto asegura que no aparezcan resultados antiguos.",
                "GhostHunter - Limpieza de Jobs",
                "OK",
                "Information"
            )
        }

        # También limpiar jobs sin nombre que puedan ser de este script
        $jobsSinNombre = Get-Job | Where-Object {
            $_.Name -eq "Job$($_.Id)" -and
            $_.State -ne "Running" -and
            ($_.Command -like "*Eliminar-Perfil*" -or $_.Command -like "*Forzar-Eliminar*")
        }

        if ($jobsSinNombre) {
            $jobsSinNombre | Remove-Job -ErrorAction SilentlyContinue
        }

    } catch {
        Write-Warning "Error al limpiar jobs huérfanos: $_"
    }
}

function Limpiar-JobsAlCerrar {
    <#
    .SYNOPSIS
        Función que se ejecuta al cerrar la aplicación para limpiar jobs pendientes
    #>
    param([System.Windows.Forms.Form]$Form)

    $Form.Add_FormClosing({
        try {
            # Detener y limpiar todos los jobs pendientes
            $jobsPendientes = Get-Job | Where-Object { $_.State -eq "Running" }
            if ($jobsPendientes) {
                $jobsPendientes | Stop-Job -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500  # Dar tiempo a que se detengan
                $jobsPendientes | Remove-Job -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignorar errores al cerrar
        }
    })
}

# Limpiar jobs huérfanos al iniciar
Limpiar-JobsHuérfanos

#endregion

#region BLOQUE - INTERFAZ GRÁFICA BASE

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "GhostHunter - Detección de Perfiles Huérfanos y Limpieza"
$form.Size = New-Object System.Drawing.Size(900, 650)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(240,240,240)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$form.ShowInTaskbar = $true
$form.MinimizeBox = $true
$form.MaximizeBox = $true
$form.Topmost = $false

# Agregar limpieza de jobs al cerrar la aplicación
Limpiar-JobsAlCerrar -Form $form

# Etiqueta Equipo
$lblEquipo = New-Object System.Windows.Forms.Label
$lblEquipo.Text = "Equipo objetivo:"
$lblEquipo.Location = New-Object System.Drawing.Point(20, 20)
$lblEquipo.Size = New-Object System.Drawing.Size(100, 20)

# Caja de texto
$txtEquipo = New-Object System.Windows.Forms.TextBox
$txtEquipo.Location = New-Object System.Drawing.Point(130, 18)
$txtEquipo.Size = New-Object System.Drawing.Size(300, 25)
$txtEquipo.Text     = $equipoInicial 

# Botón Escanear
$btnEscanear = New-Object System.Windows.Forms.Button
$btnEscanear.Text = "Escanear"
$btnEscanear.Location = New-Object System.Drawing.Point(450, 16)
$btnEscanear.Size = New-Object System.Drawing.Size(100, 28)
$btnEscanear.FlatStyle = "Flat"
$btnEscanear.BackColor = [System.Drawing.Color]::FromArgb(0,120,215)
$btnEscanear.ForeColor = [System.Drawing.Color]::White

$btnEscanear.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($equipo)) {
        $equipo = $env:COMPUTERNAME
    }
    
    # Crear ventana de progreso
    $scanProgressForm = New-Object System.Windows.Forms.Form
    $scanProgressForm.Text = "Escaneando perfiles..."
    $scanProgressForm.Size = New-Object System.Drawing.Size(400, 120)
    $scanProgressForm.StartPosition = "CenterScreen"
    $scanProgressForm.FormBorderStyle = "FixedDialog"
    $scanProgressForm.ControlBox = $false
    
    $scanProgressBar = New-Object System.Windows.Forms.ProgressBar
    $scanProgressBar.Location = New-Object System.Drawing.Point(20, 20)
    $scanProgressBar.Size = New-Object System.Drawing.Size(350, 30)
    $scanProgressBar.Style = "Marquee"  # Indeterminate progress
    
    $scanStatusLabel = New-Object System.Windows.Forms.Label
    $scanStatusLabel.Location = New-Object System.Drawing.Point(20, 60)
    $scanStatusLabel.Size = New-Object System.Drawing.Size(350, 20)
    $scanStatusLabel.Text = "Analizando perfiles en $equipo..."
    
    $scanProgressForm.Controls.AddRange(@($scanProgressBar, $scanStatusLabel))
    $scanProgressForm.Show()
    [System.Windows.Forms.Application]::DoEvents()
    
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()

    Cargar-PerfilesEnLista -EquipoObjetivo $equipo

    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $scanProgressForm.Close()
    $scanProgressForm.Dispose()
})

# ListView
$listView = New-Object System.Windows.Forms.ListView
$listView.Location = New-Object System.Drawing.Point(20, 60)
$listView.Size = New-Object System.Drawing.Size(840, 360)
$listView.View = 'Details'
$listView.FullRowSelect = $true
$listView.GridLines = $true
$listView.MultiSelect = $true
$listView.CheckBoxes = $true

$listView.Columns.Add("Usuario", 150)
$listView.Columns.Add("Último Logon", 150)
$listView.Columns.Add("Tamaño", 100)
$listView.Columns.Add("Estado", 150)
$listView.Columns.Add("SID", 300)

# Filtros
$chkAntiguos = New-Object System.Windows.Forms.CheckBox
$chkAntiguos.Text = "Mostrar Perfiles Antiguos"
$chkAntiguos.Location = New-Object System.Drawing.Point(20, 430)
$chkAntiguos.Size = New-Object System.Drawing.Size(220, 20)
$chkAntiguos.Checked = $true

$chkPequenos = New-Object System.Windows.Forms.CheckBox
$chkPequenos.Text = "Mostrar Perfiles < 1 GB"
$chkPequenos.Location = New-Object System.Drawing.Point(250, 430)
$chkPequenos.Size = New-Object System.Drawing.Size(200, 20)
$chkPequenos.Checked = $true

$chkAntiguos.Add_CheckedChanged({
    Refrescar-ListViewFiltrado -Datos $global:PerfilesCargados `
                                -FiltrarAntiguos $chkAntiguos.Checked `
                                -FiltrarPequenos $chkPequenos.Checked
})
$chkPequenos.Add_CheckedChanged({
    Refrescar-ListViewFiltrado -Datos $global:PerfilesCargados `
                                -FiltrarAntiguos $chkAntiguos.Checked `
                                -FiltrarPequenos $chkPequenos.Checked
})

# Botón eliminar
$btnEliminarMarcados = New-Object System.Windows.Forms.Button
$btnEliminarMarcados.Text = "Eliminar Perfiles Marcados"
$btnEliminarMarcados.Location = New-Object System.Drawing.Point(20, 470)
$btnEliminarMarcados.Size = New-Object System.Drawing.Size(180, 30)
$btnEliminarMarcados.FlatStyle = "Flat"
$btnEliminarMarcados.BackColor = [System.Drawing.Color]::FromArgb(0,120,215)
$btnEliminarMarcados.ForeColor = [System.Drawing.Color]::White

$btnEliminarMarcados.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($equipo)) {
        $equipo = $env:COMPUTERNAME
    }

    if ($listView.CheckedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No hay ningún perfil checkeado para eliminar.", "GhostHunter", "OK", "Warning")
        return
    }

    # Confirmación
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "¿Eliminar los perfiles checkeados en '$equipo'? Se renombrarán a _old y se forzará su eliminación.",
        "Confirmación",
        "YesNo",
        "Question"
    )

    if ($confirm -eq "Yes") {
        $resumen = Eliminar-PerfilesMarcados -Equipo $equipo -Lista $listView
        Cargar-PerfilesEnLista -EquipoObjetivo $equipo

        # El resumen ya se muestra dentro de Eliminar-PerfilesMarcados con Mostrar-ResumenProminente
        # No necesitamos mostrar otro MessageBox aquí
    }
})

# Botón limpiar temporales del sistema
$btnLimpiarSistema = New-Object System.Windows.Forms.Button
$btnLimpiarSistema.Text = "Limpiar Archivos Sistema"
$btnLimpiarSistema.Location = New-Object System.Drawing.Point(210, 470)
$btnLimpiarSistema.Size = New-Object System.Drawing.Size(160, 30)
$btnLimpiarSistema.FlatStyle = "Flat"
$btnLimpiarSistema.BackColor = [System.Drawing.Color]::FromArgb(220,53,69)
$btnLimpiarSistema.ForeColor = [System.Drawing.Color]::White

$btnLimpiarSistema.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($equipo)) {
        $equipo = $env:COMPUTERNAME
    }

    # Crear ventana de progreso
    $cleanProgressForm = New-Object System.Windows.Forms.Form
    $cleanProgressForm.Text = "Limpiando archivos del sistema..."
    $cleanProgressForm.Size = New-Object System.Drawing.Size(400, 120)
    $cleanProgressForm.StartPosition = "CenterScreen"
    $cleanProgressForm.FormBorderStyle = "FixedDialog"
    $cleanProgressForm.ControlBox = $false
    
    $cleanProgressBar = New-Object System.Windows.Forms.ProgressBar
    $cleanProgressBar.Location = New-Object System.Drawing.Point(20, 20)
    $cleanProgressBar.Size = New-Object System.Drawing.Size(350, 30)
    $cleanProgressBar.Style = "Marquee"
    
    $cleanStatusLabel = New-Object System.Windows.Forms.Label
    $cleanStatusLabel.Location = New-Object System.Drawing.Point(20, 60)
    $cleanStatusLabel.Size = New-Object System.Drawing.Size(350, 20)
    $cleanStatusLabel.Text = "Eliminando archivos temporales..."
    
    $cleanProgressForm.Controls.AddRange(@($cleanProgressBar, $cleanStatusLabel))
    $cleanProgressForm.Show()
    [System.Windows.Forms.Application]::DoEvents()

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()

    $resultado = Limpiar-ArchivosTemporales -Equipo $equipo
    
    $mensaje = "Limpieza del sistema completada:`n`n"
    foreach ($res in $resultado.Resultados) {
        $mensaje += "$($res.Ubicacion): $($res.ArchivosEliminados) archivos ($($res.TamanoEliminadoMB) MB) - $($res.Estado)`n"
    }
    $mensaje += "`nTotal eliminado: $($resultado.TotalEliminadoMB) MB"

    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $cleanProgressForm.Close()
    $cleanProgressForm.Dispose()
    [System.Windows.Forms.MessageBox]::Show($mensaje, "Limpieza del sistema", "OK", "Information")
})

# Botón limpiar cache usuarios
$btnLimpiarCache = New-Object System.Windows.Forms.Button
$btnLimpiarCache.Text = "Limpiar Cache Usuarios"
$btnLimpiarCache.Location = New-Object System.Drawing.Point(380, 470)
$btnLimpiarCache.Size = New-Object System.Drawing.Size(160, 30)
$btnLimpiarCache.FlatStyle = "Flat"
$btnLimpiarCache.BackColor = [System.Drawing.Color]::FromArgb(255,193,7)
$btnLimpiarCache.ForeColor = [System.Drawing.Color]::Black

$btnLimpiarCache.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($equipo)) {
        $equipo = $env:COMPUTERNAME
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "¿Limpiar archivos de cache de usuarios en '$equipo'?`n`nSe eliminarán archivos de:`n- AppData\Local\Temp`n- Cache IE/Chrome/Edge",
        "Confirmar limpieza de cache",
        "YesNo",
        "Question"
    )

    if ($confirm -eq "Yes") {
        # Crear ventana de progreso
        $cacheProgressForm = New-Object System.Windows.Forms.Form
        $cacheProgressForm.Text = "Limpiando cache de usuarios..."
        $cacheProgressForm.Size = New-Object System.Drawing.Size(400, 120)
        $cacheProgressForm.StartPosition = "CenterScreen"
        $cacheProgressForm.FormBorderStyle = "FixedDialog"
        $cacheProgressForm.ControlBox = $false
        
        $cacheProgressBar = New-Object System.Windows.Forms.ProgressBar
        $cacheProgressBar.Location = New-Object System.Drawing.Point(20, 20)
        $cacheProgressBar.Size = New-Object System.Drawing.Size(350, 30)
        $cacheProgressBar.Style = "Marquee"
        
        $cacheStatusLabel = New-Object System.Windows.Forms.Label
        $cacheStatusLabel.Location = New-Object System.Drawing.Point(20, 60)
        $cacheStatusLabel.Size = New-Object System.Drawing.Size(350, 20)
        $cacheStatusLabel.Text = "Eliminando archivos de cache..."
        
        $cacheProgressForm.Controls.AddRange(@($cacheProgressBar, $cacheStatusLabel))
        $cacheProgressForm.Show()
        [System.Windows.Forms.Application]::DoEvents()

        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        [System.Windows.Forms.Application]::DoEvents()

        $resultado = Limpiar-CacheUsuarios -Equipo $equipo
        
        $mensaje = "Limpieza de cache completada:`n`n"
        if ($resultado.Resultados.Count -gt 0) {
            foreach ($res in $resultado.Resultados) {
                $mensaje += "$($res.Usuario): $($res.ArchivosEliminados) archivos ($($res.TamanoEliminadoMB) MB) - $($res.Estado)`n"
            }
        } else {
            $mensaje += "No se encontraron archivos para eliminar.`n"
        }
        $mensaje += "`nTotal eliminado: $($resultado.TotalEliminadoMB) MB"

        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $cacheProgressForm.Close()
        $cacheProgressForm.Dispose()
        [System.Windows.Forms.MessageBox]::Show($mensaje, "Limpieza de cache", "OK", "Information")
    }
})

# Botón exportar
$btnExportar = New-Object System.Windows.Forms.Button
$btnExportar.Text = "Exportar resultados"
$btnExportar.Location = New-Object System.Drawing.Point(550, 470)
$btnExportar.Size = New-Object System.Drawing.Size(140, 30)
$btnExportar.FlatStyle = "Flat"
$btnExportar.BackColor = [System.Drawing.Color]::FromArgb(0,120,215)
$btnExportar.ForeColor = [System.Drawing.Color]::White

$btnExportar.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($equipo)) {
        $equipo = $env:COMPUTERNAME
    }
    $res = Exportar-PerfilesCSV -Lista $listView -Equipo $equipo
    [System.Windows.Forms.MessageBox]::Show($res, "Exportar resultados", "OK", "Information")
})

# Botón informe
$btnInforme = New-Object System.Windows.Forms.Button
$btnInforme.Text = "Generar informe"
$btnInforme.Location = New-Object System.Drawing.Point(700, 470)
$btnInforme.Size = New-Object System.Drawing.Size(140, 30)
$btnInforme.FlatStyle = "Flat"
$btnInforme.BackColor = [System.Drawing.Color]::FromArgb(0,120,215)
$btnInforme.ForeColor = [System.Drawing.Color]::White

$btnInforme.Add_Click({
    $equipo = $txtEquipo.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($equipo)) {
        $equipo = $env:COMPUTERNAME
    }
    $res = Generar-InformeTXT -Datos $global:PerfilesCargados -Equipo $equipo
    [System.Windows.Forms.MessageBox]::Show($res, "Generar informe", "OK", "Information")
})

# Etiqueta de información
$lblInfo = New-Object System.Windows.Forms.Label
$lblInfo.Text = "Perfiles protegidos (azul) = en uso. Eliminables (rojo) = < 1GB +30d o +91d inactivo. Limpieza: Archivos Sistema | Cache Usuarios"
$lblInfo.Location = New-Object System.Drawing.Point(20, 510)
$lblInfo.Size = New-Object System.Drawing.Size(840, 40)
$lblInfo.ForeColor = [System.Drawing.Color]::DarkSlateGray
$lblInfo.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)

$form.Controls.AddRange(@(
    $lblEquipo, $txtEquipo, $btnEscanear, $listView,
    $chkAntiguos, $chkPequenos,
    $btnEliminarMarcados, $btnLimpiarSistema, $btnLimpiarCache, $btnExportar, $btnInforme,
    $lblInfo
))

$form.Show()

while ($form.Visible) {
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 100
}