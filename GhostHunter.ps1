param(
    [string]$Equipo = $env:COMPUTERNAME
)

$equipoInicial = $Equipo  # Leemos lo que nos pasen
if (-not $equipoInicial) {
    $equipoInicial = $env:COMPUTERNAME
}

#region BLOQUE - FUNCIONES DE ANÁLISIS DE PERFILES

function Get-PerfilesLocales {
    param(
        [string]$Equipo = $env:COMPUTERNAME
    )

    # Lista de exclusión extendida
    $excluir = @(
        # Cuentas del sistema
        'Default', 'Default User', 'Public', 'All Users', 'desktop.ini',
        'Administrador', 'systemprofile', 'LocalService', 'NetworkService',
        'SYSTEM', 'Invitado', 'Guest', 'WDAGUtilityAccount', 'Administrador de la empresa', 'Symantec Task Server AppPool',

        # Cuentas especiales de Windows
        'appmodel', 'sshd', 'ssh', 'DWM-1', 'UMFD-0', 'UMFD-1', 'DefaultAccount',
        'ADMIN$', 'ADMIN', 'DefaultAppPool', 'Classic .NET AppPool',

        # Perfiles .NET
        '.NET v2.0', '.NET v4.0', '.NET v4.5', '.NET v4.5 Classic', '.NET v2.0 Classic', '.NET CLR',

        # Servicios conocidos
        'Symantec', 'Symantec Task Server', 'Sophos', 'McAfee', 'TrendMicro', 'ESET', 
        'SQLServer', 'SQLAgent', 'ReportServer', 'AppFabric', 'Ssms', 'W3SVC', 'IIS_IUSRS',

        # Otros identificadores típicos de perfiles temporales o técnicos
        'TEMP', 'TEMPUSER', 'tsclient', 'UPNROAM', 'RECOVERY', 'UpdatusUser', 'OneDriveTemp',
        'HomeGroupUser$', 'SAPService', 'svc_', 'SUPPORT_', 'hpuser'
    )

    $perfiles = @()

    try {
        $RutaPerfiles = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Equipo)
        $SubKey = $RegKey.OpenSubKey($RutaPerfiles)

        foreach ($SID in $SubKey.GetSubKeyNames()) {
            $SubClave    = $SubKey.OpenSubKey($SID)
            $rutaPerfil  = $SubClave.GetValue("ProfileImagePath")
            if ([string]::IsNullOrWhiteSpace($rutaPerfil)) { continue }

            $nombre = [System.IO.Path]::GetFileName($rutaPerfil)
            if ($excluir -contains $nombre) { continue }

            $tamano = 0
            $ultimaMod = $null
            if ($rutaPerfil -match "^C:\\Users\\") {
                $relativePath = $rutaPerfil.Substring(3)
                $rutaUNC = "\\$Equipo\C$\" + $relativePath

                if (Test-Path $rutaUNC) {
                    $tamano = [Math]::Round(
                        (Get-ChildItem -Path $rutaUNC -Recurse -ErrorAction SilentlyContinue |
                         Measure-Object -Property Length -Sum).Sum / 1MB, 2
                    )
                    $info = Get-Item -Path $rutaUNC -ErrorAction SilentlyContinue
                    $ultimaMod = $info.LastWriteTime
                }
            }
            if (-not $ultimaMod) { $ultimaMod = Get-Date }

            $estado = "Activo"
            if ($tamano -lt 0.5) {
                $estado = "Eliminable (<0.5MB)"
            }
            elseif ($ultimaMod -lt (Get-Date).AddDays(-90)) {
                $estado = "Antiguo"
            }

            $perfiles += [PSCustomObject]@{
                Usuario   = $nombre
                Ruta      = $rutaPerfil
                UltimaMod = $ultimaMod
                TamanoMB  = $tamano
                SID       = $SID
                Estado    = $estado
            }
        }
        $RegKey.Close()
    } catch {
        Write-Warning "No se pudo acceder al registro remoto de $Equipo. Error: $_"
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

function Remove-ClaveRegistro {
    param (
        [string]$Equipo,
        [string]$SID
    )
    try {
        $ClaveEliminar = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
        $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Equipo)
        if ($RegKey.OpenSubKey($ClaveEliminar)) {
            $RegKey.DeleteSubKeyTree($ClaveEliminar)
        }
        $RegKey.Close()
        return "✔ Clave de registro eliminada."
    } catch {
        return "❌ Error al eliminar la clave: $_"
    }
}

function Forzar-EliminarCarpeta {
    param([string]$PathUNC)

    try {
        # 1º Intento con PowerShell
        try {
            Remove-Item -Path $PathUNC -Recurse -Force -ErrorAction Stop
            Write-Host "✅ Carpeta eliminada con Remove-Item: $PathUNC"
            return
        }
        catch {
            Write-Warning "❌ Remove-Item falló. Intentando con cmd.exe / rd /s /q..."
        }

        # 2º Intento con cmd.exe (más agresivo)
        $escapedPath = $PathUNC -replace '"', '""'
        $cmd = "rd /s /q `"$escapedPath`""
        cmd.exe /c $cmd | Out-Null

        if (Test-Path $PathUNC) {
            Write-Warning "❌ No se pudo eliminar la carpeta con cmd.exe. Se marcará para eliminar tras reinicio."

            # 3º Registrar para borrado tras reinicio
            $equipo = ($PathUNC -split "\\")[2]
            $clave = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $equipo)
            $sessionKey = $clave.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager", $true)

            # Convertir UNC a ruta local (C:\...)
            $rutaLocal = $PathUNC -replace "^\\\\[^\\]+\\C\$", "C:"
            $pendientes = $sessionKey.GetValue("PendingFileRenameOperations", @())
            $nuevoValor = $pendientes + $rutaLocal + "\0"
            $sessionKey.SetValue("PendingFileRenameOperations", $nuevoValor, [Microsoft.Win32.RegistryValueKind]::MultiString)

            Write-Warning "🕒 Carpeta registrada para borrado tras reinicio: $rutaLocal"
        }
        else {
            Write-Host "✅ Carpeta eliminada con cmd.exe: $PathUNC"
        }
    }
    catch {
        Write-Warning "❌ Error inesperado en Forzar-EliminarCarpeta: $_"
    }
}


#endregion

#region BLOQUE - ELIMINACIÓN DE PERFIL COMPLETO (RENOMBRA Y BORRA FORZADO)

function Eliminar-PerfilCompleto {
    param (
        [string]$Equipo,
        [string]$RutaPerfil,
        [string]$SID
    )
    # 1) Eliminar clave en ProfileList
    $resultado = Remove-ClaveRegistro -Equipo $Equipo -SID $SID

    # 2) Renombrar la carpeta a _old
    $rutaUNC = $RutaPerfil -replace "^[a-zA-Z]:", "\\$Equipo\C$"
    if (Test-Path $rutaUNC) {
        $nombreActual = Split-Path $rutaUNC -Leaf
        $carpetaPadre = Split-Path $rutaUNC -Parent
        $rutaOld = Join-Path $carpetaPadre ($nombreActual + "_old")

        try {
            Rename-Item -Path $rutaUNC -NewName ($nombreActual + "_old")
            $resultado += " | ✔ Renombrada a: $($nombreActual + "_old")"

            # 3) Forzar eliminación
            try {
                Forzar-EliminarCarpeta -PathUNC $rutaOld
                $resultado += " | ✔ Carpeta _old eliminada."
            }
            catch {
                $resultado += " | ❌ Error al forzar eliminación: $_"
            }
        } catch {
            $resultado += " | ❌ Error al renombrar la carpeta: $_"
        }
    }
    else {
        $resultado += " | ⚠ Carpeta no encontrada."
    }

    return $resultado
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
        if ($estado -eq "Antiguo" -or $estado -eq "Eliminable (<0.5MB)") {
            $perfilesAEliminar += [PSCustomObject]@{
                Usuario = $item.SubItems[0].Text
                SID     = $item.SubItems[4].Text
                Ruta    = "C:\Users\$($item.SubItems[0].Text)"
            }
        }
    }

    # Definir el tamaño del bloque (ajusta según convenga)
    $batchSize = 5
    $jobs = @()

    # Procesar los perfiles en bloques usando jobs paralelos
    for ($i = 0; $i -lt $perfilesAEliminar.Count; $i += $batchSize) {
        $endIndex = [Math]::Min($i + $batchSize - 1, $perfilesAEliminar.Count - 1)
        $batch = $perfilesAEliminar[$i..$endIndex]

        $job = Start-Job -ScriptBlock {
            param($batchInterno, $EquipoInterno)
            $resultadosLocal = @()
            foreach ($p in $batchInterno) {
                # Llamada a la función que elimina el perfil completo
                $resultado = Eliminar-PerfilCompleto -Equipo $EquipoInterno -RutaPerfil $p.Ruta -SID $p.SID
                $resultadosLocal += [PSCustomObject]@{
                    Usuario   = $p.Usuario
                    Resultado = $resultado
                }
            }
            return $resultadosLocal
        } -ArgumentList $batch, $Equipo

        $jobs += $job
    }

    # Esperar a que todos los jobs terminen y recoger resultados
    Wait-Job -Job $jobs
    $todosResultados = $jobs | Receive-Job
    Remove-Job -Job $jobs

    # Separar perfiles eliminados y con error
    $eliminados = @()
    $errores = @()
    foreach ($res in $todosResultados) {
        if ($res.Resultado -match "Error" -or $res.Resultado -match "❌") {
            $errores += "$($res.Usuario) => $($res.Resultado)"
        } else {
            $eliminados += "$($res.Usuario) => $($res.Resultado)"
        }
    }

    $resumen = "Perfiles procesados:`n" + ($eliminados -join "`n")
    if ($errores.Count -gt 0) {
        $resumen += "`n`nErrores:`n" + ($errores -join "`n")
    }

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
            UltimaMod = $item.SubItems[1].Text
            TamanoMB  = $item.SubItems[2].Text
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

    # Lógica: OR cuando ambos están marcados
    if (-not $FiltrarAntiguos -and -not $FiltrarPequenos) {
        $filtrados = $Datos
    }
    elseif ($FiltrarAntiguos -and $FiltrarPequenos) {
        $filtrados = $Datos | Where-Object {
            $_.Estado -eq "Antiguo" -or $_.Estado -eq "Eliminable (<0.5MB)"
        }
    }
    elseif ($FiltrarAntiguos) {
        $filtrados = $Datos | Where-Object { $_.Estado -eq "Antiguo" }
    }
    else {
        $filtrados = $Datos | Where-Object { $_.Estado -eq "Eliminable (<0.5MB)" }
    }

    foreach ($perfil in $filtrados) {
        $item = New-Object System.Windows.Forms.ListViewItem($perfil.Usuario)
        $item.SubItems.Add($perfil.UltimaMod.ToString("yyyy-MM-dd HH:mm"))
        $item.SubItems.Add($perfil.TamanoMB.ToString("0.00"))
        $item.SubItems.Add($perfil.Estado)
        $item.SubItems.Add($perfil.SID)

        switch ($perfil.Estado) {
            "Activo" {
                $item.ForeColor = [System.Drawing.Color]::Green
            }
            "Antiguo" {
                $item.ForeColor = [System.Drawing.Color]::DarkOrange
            }
            "Eliminable (<0.5MB)" {
                $item.ForeColor = [System.Drawing.Color]::Red
            }
        }

        # Marcar items si coincide con el filtro
        if ($FiltrarAntiguos -and $perfil.Estado -eq "Antiguo") {
            $item.Checked = $true
        }
        if ($FiltrarPequenos -and $perfil.Estado -eq "Eliminable (<0.5MB)") {
            $item.Checked = $true
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

    $activos     = $Datos | Where-Object { $_.Estado -eq "Activo" }
    $antiguos    = $Datos | Where-Object { $_.Estado -eq "Antiguo" }
    $eliminables = $Datos | Where-Object { $_.Estado -eq "Eliminable (<0.5MB)" }

    $lineas = @()
    $lineas += "===== Informe de Perfiles - GhostHunter ====="
    $lineas += "Equipo analizado : $Equipo"
    $lineas += "Fecha/Hora       : $($ahora.ToString("yyyy-MM-dd HH:mm"))"
    $lineas += ""
    $lineas += "Total perfiles encontrados : $($Datos.Count)"
    $lineas += "  - Activos     : $($activos.Count)"
    $lineas += "  - Antiguos    : $($antiguos.Count)"
    $lineas += "  - Eliminables : $($eliminables.Count)"
    $lineas += ""
    $lineas += "----- Detalle por perfil -----"

    foreach ($p in $Datos) {
        $lineas += ""
        $lineas += "Usuario    : $($p.Usuario)"
        $lineas += "Últ. Modif.: $($p.UltimaMod.ToString("yyyy-MM-dd HH:mm"))"
        $lineas += "Tamaño     : $($p.TamanoMB.ToString("0.00")) MB"
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

#region BLOQUE - INTERFAZ GRÁFICA BASE

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "GhostHunter - Detección de Perfiles Huérfanos"
$form.Size = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(240,240,240)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$form.ShowInTaskbar = $true
$form.MinimizeBox = $true
$form.MaximizeBox = $true
$form.Topmost = $false

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
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()

    Cargar-PerfilesEnLista -EquipoObjetivo $equipo

    $form.Cursor = [System.Windows.Forms.Cursors]::Default
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
$listView.Columns.Add("Última Modif.", 150)
$listView.Columns.Add("Tamaño (MB)", 100)
$listView.Columns.Add("Estado", 150)
$listView.Columns.Add("SID", 300)

# Filtros
$chkAntiguos = New-Object System.Windows.Forms.CheckBox
$chkAntiguos.Text = "Mostrar Perfiles Antiguos"
$chkAntiguos.Location = New-Object System.Drawing.Point(20, 430)
$chkAntiguos.Size = New-Object System.Drawing.Size(220, 20)
$chkAntiguos.Checked = $true

$chkPequenos = New-Object System.Windows.Forms.CheckBox
$chkPequenos.Text = "Mostrar Perfiles < 0.5 MB"
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
$btnEliminarMarcados.Size = New-Object System.Drawing.Size(200, 30)
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

        if ($resumen -match "Errores:") {
            [System.Windows.Forms.MessageBox]::Show($resumen, "Errores al eliminar", "OK", "Error")
        } else {
            [System.Windows.Forms.MessageBox]::Show($resumen, "Eliminación", "OK", "Information")
        }
    }
})

# Botón exportar
$btnExportar = New-Object System.Windows.Forms.Button
$btnExportar.Text = "Exportar resultados"
$btnExportar.Location = New-Object System.Drawing.Point(440, 470)
$btnExportar.Size = New-Object System.Drawing.Size(160, 30)
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
$btnInforme.Location = New-Object System.Drawing.Point(610, 470)
$btnInforme.Size = New-Object System.Drawing.Size(160, 30)
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

$form.Controls.AddRange(@(
    $lblEquipo, $txtEquipo, $btnEscanear, $listView,
    $chkAntiguos, $chkPequenos,
    $btnEliminarMarcados, $btnExportar, $btnInforme
))

$form.Show()

while ($form.Visible) {
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 100
}
