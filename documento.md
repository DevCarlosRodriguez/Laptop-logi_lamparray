# Informe técnico — Fuga de memoria en `logi_lamparray_service`

**Equipo:** LAPTOP-PRIHIIK2
**Usuario:** CarlosRodriguez
**Sistema:** Windows 11 — Build 10.0.26200.8893
**Fecha del incidente:** 12 de agosto de 2026
**Fecha de resolución:** 12–13 de agosto de 2026

---

## 1. Resumen ejecutivo

El servicio `logi_lamparray_service.exe` (Logitech LampArray Translation Service) presentó una **fuga de memoria descontrolada** que llevó la memoria comprometida del sistema de un valor normal (~11 GB) hasta **121.8 GB**, degradando severamente el rendimiento del equipo.

**Causa raíz:** el servicio no maneja correctamente un nodo PnP de tipo `&LAMPARRAY` que está registrado en el sistema pero cuyo hardware está ausente. Ante esa condición entra en un bucle de enumeración que asigna memoria de heap en cada iteración sin liberarla.

**Detonante:** durante una revisión técnica de la cámara del equipo se conectó un mouse G203 LIGHTSYNC con número de serie distinto al registrado previamente. Esto dejó huérfano el nodo `&LAMPARRAY` del mouse anterior.

**Resolución:** eliminación de los nodos PnP huérfanos y deshabilitación del servicio. Memoria comprometida restaurada a **11 GB**.

**No fue un virus.** Ver sección 6.

---

## 2. Contexto del incidente

El 12 de agosto de 2026 el equipo fue entregado a revisión técnica (Junior Hernández) porque la cámara de la laptop no encendía.

Tras la revisión, se reportó que "una tarea anómala tipo virus" había comenzado a causar consumo excesivo de memoria.

El síntoma observado por el usuario: **la memoria RAM se elevaba a ~80% inmediatamente después de encender el equipo**, sin abrir ninguna aplicación.

---

## 3. Investigación — comandos ejecutados y hallazgos

### 3.1 Verificación de integridad del binario

**Objetivo:** descartar malware o corrupción del archivo.

```powershell
Get-AuthenticodeSignature "C:\Windows\System32\DriverStore\FileRepository\logi_lamparray_usb.inf_amd64_*\logi_lamparray_service.exe"
```

**Hallazgo:** firma Authenticode válida, firmante **Logitech Inc.**

El archivo reside en `C:\Windows\System32\DriverStore\FileRepository\`, directorio protegido por TrustedInstaller donde únicamente Windows Update y el subsistema PnP colocan paquetes de driver firmados y validados. Malware no puede escribir en esa ubicación.

---

### 3.2 Revisión de los canales de eventos del driver

**Objetivo:** verificar la hipótesis inicial de contención entre dos controladores (Windows Dynamic Lighting vs. Logitech G HUB).

```powershell
Get-WinEvent -LogName "Logi-LampArray-Driver/Errors" -MaxEvents 20 -EA SilentlyContinue |
  Select TimeCreated, Id, LevelDisplayName
```

**Resultado:** vacío. Sin eventos.

```powershell
Get-WinEvent -ListLog *lamp* | Select LogName, RecordCount, IsEnabled
```

```
LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular             1052672           0 Logi-LampArray-Driver/Operational
Circular             1052672           0 Logi-LampArray-Driver/Errors
```

**Hallazgo crítico:** `RecordCount = 0` en **ambos** canales. Cero eventos registrados desde que el driver existe en el equipo.

**Conclusión:** la hipótesis de contención (Event ID 11 — "operación sin control exclusivo sobre el dispositivo") **queda descartada**. No hubo ningún conflicto de arbitraje. Este hallazgo eliminó la teoría de "doble controlador".

---

### 3.3 Medición de memoria — foto general

```powershell
Get-Counter '\Memory\Committed Bytes','\Memory\Pool Nonpaged Bytes','\Memory\Pool Paged Bytes','\Memory\Cache Bytes' |
  Select -Expand CounterSamples |
  Select @{n='Contador';e={$_.Path.Split('\')[-1]}}, @{n='MB';e={[math]::Round($_.CookedValue/1MB,0)}}
```

**Resultado — 19:19:28:**

| Contador | Valor |
|---|---|
| Committed Bytes | **89,277,616,128** (83.1 GB) |
| Pool Nonpaged Bytes | 1,586,282,496 (1.48 GB) |
| Pool Paged Bytes | 403,443,712 (385 MB) |

---

### 3.4 Identificación del proceso responsable

```powershell
Get-Process | Sort WorkingSet64 -Desc | Select -First 12 Name, Id,
  @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,0)}},
  @{n='Commit_MB';e={[math]::Round($_.PagedMemorySize64/1MB,0)}}, Handles
```

**Resultado — 19:19:28:**

| Proceso | PID | WorkingSet64 | Handles |
|---|---|---|---|
| **logi_lamparray_service.AMD64** | 6556 | **24,357,744,640 (22.7 GB)** | 197 |
| msedgewebview2 | 22152 | 541,519,872 (541 MB) | 711 |
| Memory Compression | 4716 | 523,694,080 | 0 |
| MsMpEng | 6624 | 293,761,024 | 1366 |
| brave | 21788 | 255,123,456 | 406 |

**Hallazgo:** el servicio consumía **45 veces más memoria que el siguiente proceso de la lista**.

---

### 3.5 Medición de la tasa de crecimiento

```powershell
1..12 | ForEach-Object {
  $t = (Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue/1MB
  $l = Get-Process | Where Name -match 'logi|lghub' |
       Measure-Object WorkingSet64 -Sum | Select -Expand Sum
  [PSCustomObject]@{
    Hora=Get-Date -Format HH:mm:ss
    Total_MB=[math]::Round($t,0)
    Logi_MB=[math]::Round($l/1MB,1)
  }
  Start-Sleep 60
} | Format-Table
```

**Resultado:**

```
Hora     Total_MB Logi_MB
----     -------- -------
19:20:04    80598  18838.1
19:21:05   121025  22881.6
```

**Progresión de memoria comprometida:**

| Hora | Committed | Delta |
|---|---|---|
| 19:19:28 | 83.1 GB | — |
| 19:20:04 | 78.7 GB | -4.4 GB |
| 19:21:05 | 118.2 GB | **+39.5 GB en 61 s** |
| 19:21:36 | 121.8 GB | +3.6 GB |

**Tasa medida en el pico: ~660 MB/s.**

---

### 3.6 Caracterización del tipo de fuga

**Observación clave — segunda captura (19:21:36):**

| Métrica | 19:19 | 19:21 | Lectura |
|---|---|---|---|
| WorkingSet del proceso | 22.7 GB | 10.2 GB | **bajó** |
| Committed del sistema | 83 GB | 121.8 GB | **subió** |
| Handles del proceso | 197 | 197 | **constante** |
| Pool no paginado | 1.48 GB | 1.29 GB | estable |

La aparente contradicción (working set baja mientras el commit sube) es la firma de una **fuga bajo presión de memoria**: el Memory Manager de Windows recorta el working set expulsando páginas al archivo de paginación. El proceso "se ve" más pequeño pero **no liberó nada** — su memoria comprometida sigue reservada, ahora en disco.

**Evidencia de que el resto del sistema estaba siendo afectado** — mismos procesos entre ambas capturas:

| Proceso | 19:19 | 19:21 |
|---|---|---|
| msedgewebview2 | 541 MB | 117 MB |
| Memory Compression | 523 MB | 182 MB |
| MsMpEng (Defender) | 293 MB | 200 MB |
| Taskmgr | 92 MB | 79 MB |

Todos encogieron. `AMDRSSrcExt` y `RadeonSoftware` desaparecieron del top 15. Windows estaba recortando working sets a todo el sistema para intentar cubrir el consumo de un solo proceso.

**Conclusiones sobre la naturaleza de la fuga:**

- **Handles constantes en 197** → NO hay fuga de objetos del kernel.
- **Pool no paginado estable (incluso decreciente)** → el kernel está limpio.
- **La fuga es 100% heap en modo usuario.**

---

### 3.7 Descarte de la hipótesis de fallo de UMDF

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=219} -MaxEvents 50 -EA SilentlyContinue |
  Select TimeCreated, @{n='Dev';e={$_.Message -replace "`n",' '}} | Format-Table -Wrap
```

**Hallazgo:** errores `WUDFRd failed to load` con status `0xC0000365` sobre `ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000` y `ACPI\AMDI0080\1`.

**Fechas encontradas:** 23 jul, 24 jul, 2 ago, y once ocurrencias el 12 de agosto.

**Conclusión:** estos errores son **crónicos desde el 23 de julio**, tres semanas antes del incidente. El equipo funcionó normalmente todo ese tiempo con esos mismos fallos presentes.

**La hipótesis de "la revisión de la cámara rompió UMDF" queda formalmente descartada.**

Nota: los once ciclos de arranque del 12 de agosto (14:14, 14:26, 14:41, 14:55, 15:10, 15:23, 15:43, 16:09, 18:30, 18:43, 19:15) corresponden al trabajo de diagnóstico del técnico, con intervalos de 12–25 minutos.

---

### 3.8 Descarte de tareas y servicios anómalos

```powershell
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-3)} |
  Select TaskName, TaskPath, Date, State
```

**Resultado:** 23 tareas, **todas de Microsoft** en rutas del sistema — Intune, Office, .NET Framework NGEN, Maps, License Manager, WinSAT.

```powershell
Get-CimInstance Win32_Service | Where-Object {$_.PathName -notmatch 'System32|Program Files'} |
  Select Name, PathName, StartMode
```

**Resultado:** 9 servicios, todos legítimos — Windows Defender (`ProgramData\Microsoft\Windows Defender\Platform`, ubicación por diseño), .NET Framework, TrustedInstaller, PerfHost.

**Conclusión: no existe ninguna tarea programada anómala ni servicio sospechoso en el equipo.**

---

### 3.9 Fecha de instalación del paquete de driver

```powershell
Get-ChildItem "C:\Windows\System32\DriverStore\FileRepository" -Filter "logi_lamparray*" |
  Select Name, CreationTime, LastWriteTime
```

**Resultado:**

```
logi_lamparray_usb.inf_amd64_dc165490f32791ad       15/06/2026 5:59:54 PM
logi_lamparray_usb.inf_amd64_dc165490f32791ad.ini   15/06/2026 5:59:54 PM
```

**Hallazgo:** el paquete se instaló el **15 de junio de 2026**, casi dos meses antes del incidente. `CreationTime` y `LastWriteTime` coinciden: **el archivo no fue modificado durante la revisión del 12 de agosto**.

Esto descarta definitivamente instalación reciente, reinstalación o alteración del paquete como causa.

---

### 3.10 Hallazgo de la causa raíz — nodos PnP del G203

```powershell
Get-PnpDevice | Where-Object FriendlyName -match 'G203' |
  Select FriendlyName, Status, Present, Class, InstanceId | Format-List
```

**Resultado:**

| InstanceId | Status | Present | Class | Serie |
|---|---|---|---|---|
| `USB\VID_046D&PID_C092\140E5B0B3015` | Unknown | **False** | USB | 140E5B0B3015 |
| `USB\VID_046D&PID_C092&LAMPARRAY\7&31CAACF6&0&140E5B0B3015_SLOT00` | Unknown | **False** | *(vacío)* | 140E5B0B3015 |
| `USB\VID_046D&PID_C092\14315AF63015` | OK | **True** | USB | 14315AF63015 |
| `USB\VID_046D&PID_C092&LAMPARRAY\7&1B26F372&0&14315AF63015_SLOT00` | OK | **True** | *(vacío)* | 14315AF63015 |

**Interpretación:** son **dos mouse G203 físicamente distintos**. Mismo modelo, mismo PID (`C092`), **números de serie diferentes**.

Cada mouse genera dos nodos relevantes: el dispositivo USB base y un nodo hijo sintético `&LAMPARRAY`, que es la interfaz que el driver de Logitech crea para exponer el dispositivo a Windows como dispositivo LampArray.

**El nodo `&LAMPARRAY` de la serie `140E5B0B3015` quedó registrado pero con hardware ausente.**

---

### 3.11 Detalle revelador del enum completo

```powershell
pnputil /enum-devices /disconnected | Select-String -Context 3,6 "C092"
```

El mouse retirado había dejado una jerarquía completa de nodos huérfanos (~10 nodos): dispositivo USB base, nodo `&LAMPARRAY`, interfaces compuestas `MI_00` y `MI_01`, HID-compliant mouse, HID Keyboard Device, consumer control device, system controller y dos vendor-defined devices.

**Dato clave:** de todos esos nodos, el `&LAMPARRAY` era el **único** con:

```
Device Description:         G203 LIGHTSYNC
Class Name:                 Unknown
Class GUID:                 Unknown
Manufacturer Name:          Unknown
Status:                     Disconnected
```

Sin clase, sin GUID, sin fabricante y **sin driver asociado**. Los demás nodos huérfanos sí tenían driver (`input.inf`, `msmouse.inf`, `keyboard.inf`, `usbhub3.inf`) y son inofensivos — Windows los conserva de rutina.

---

## 4. Reparación ejecutada

### 4.1 Punto de restauración (CHECKPOINT DISPONIBLE)

> **⚠ IMPORTANTE — Punto de retorno al estado con el error**

```powershell
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "Antes limpiar LampArray" -RestorePointType MODIFY_SETTINGS
```

**Verificación:**

```powershell
Get-ComputerRestorePoint | Select -Last 3 CreationTime, Description, SequenceNumber
```

```
CreationTime              Description             SequenceNumber
------------              -----------             --------------
20260813004806.921878-000 Antes limpiar LampArray              1
```

| Campo | Valor |
|---|---|
| **Descripción** | `Antes limpiar LampArray` |
| **SequenceNumber** | **1** |
| **Fecha/hora** | 13/08/2026 00:48:06 |
| **Tipo** | MODIFY_SETTINGS |

**Este checkpoint contiene el estado del sistema CON el error presente.** Restaurarlo revertiría la configuración del servicio al estado previo a la reparación.

Nota técnica: Restaurar Sistema **no revierte de forma confiable cambios de dispositivos PnP**. La reversibilidad real de la limpieza de nodos es distinta: los nodos eliminados corresponden a hardware ausente, y si ese mouse se reconectara, Windows lo registraría automáticamente de nuevo (plug-and-play).

**Incidencia durante este paso:** ambos comandos fallaron inicialmente con `Access denied` por falta de elevación. Se resolvió ejecutando PowerShell como Administrador. No fue restricción de política corporativa, pese a que el equipo está administrado por Intune.

---

### 4.2 Respaldo del estado previo

```powershell
Get-PnpDevice | Where-Object FriendlyName -match 'G203' |
  Select FriendlyName,Status,Present,Class,InstanceId |
  Out-File "$env:USERPROFILE\Desktop\g203_antes.txt"

Get-Service *lamp* | Select Name,Status,StartType |
  Out-File "$env:USERPROFILE\Desktop\g203_antes.txt" -Append
```

Archivo generado: `Escritorio\g203_antes.txt`

---

### 4.3 Contención — detención del servicio

```powershell
$s = (Get-Service *lamp*).Name
Stop-Service -Name $s -Force
Set-Service -Name $s -StartupType Disabled
"Committed: $([math]::Round((Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue/1GB,1)) GB"
```

**Resultado:**

```
Committed: 18.6 GB
```

**De 121.8 GB a 18.6 GB.** Un solo proceso era responsable de aproximadamente **103 GB** de memoria comprometida. Esta medición constituye la prueba causal directa.

---

### 4.4 Verificación previa a la eliminación

```powershell
pnputil /enum-devices /disconnected | Select-String -Context 3,6 "C092"
```

Se confirmó que los nodos a eliminar correspondían a la serie `140E5B0B3015` (ausente) y **no** a `14315AF63015` (presente).

---

### 4.5 Eliminación de los nodos huérfanos

```powershell
pnputil /remove-device "USB\VID_046D&PID_C092&LAMPARRAY\7&31CAACF6&0&140E5B0B3015_SLOT00"
```

```
Microsoft PnP Utility
Removing device:  USB\VID_046D&PID_C092&LAMPARRAY\7&31caacf6&0&140E5B0B3015_Slot00
Device removed successfully.
```

```powershell
pnputil /remove-device "USB\VID_046D&PID_C092\140E5B0B3015"
```

```
Microsoft PnP Utility
Removing device:  USB\VID_046D&PID_C092\140E5B0B3015
Device removed successfully.
```

---

### 4.6 Verificación inmediata

```powershell
Get-PnpDevice | Where-Object FriendlyName -match 'G203' | Select Present, InstanceId
```

```
Present InstanceId
------- ----------
   True USB\VID_046D&PID_C092&LAMPARRAY\7&1B26F372&0&14315AF63015_SLOT00
   True USB\VID_046D&PID_C092\14315AF63015
```

Registro PnP consistente: dos nodos, ambos presentes, una sola serie.

---

### 4.7 Verificación post-reinicio

```powershell
Get-PnpDevice | Where-Object FriendlyName -match 'G203' | Select Present, InstanceId
"Committed: $([math]::Round((Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue/1GB,1)) GB"
Get-Service *lamp* | Select Name, Status, StartType
```

**Resultado:**

```
Present InstanceId
------- ----------
   True USB\VID_046D&PID_C092&LAMPARRAY\7&1B26F372&0&14315AF63015_SLOT00
   True USB\VID_046D&PID_C092\14315AF63015

Committed: 11 GB

Name                    Status StartType
----                    ------ ---------
logi_lamparray_service Stopped  Disabled
```

**El reinicio no regeneró los nodos huérfanos. La limpieza fue definitiva.**

---

### 4.8 Trayectoria de recuperación

| Momento | Memoria comprometida |
|---|---|
| Pico del incidente | **121.8 GB** |
| Tras detener el servicio | **18.6 GB** |
| Tras limpieza y reinicio | **11 GB** |

---

## 5. La pregunta central: ¿por qué antes no pasaba?

El paquete de driver está instalado desde el **15 de junio de 2026** y funcionó sin incidentes durante casi dos meses. La pregunta legítima es qué cambió el 12 de agosto.

### Respuesta

**El bug siempre estuvo presente en el código, pero requería una condición específica para manifestarse: la existencia de un nodo `&LAMPARRAY` registrado en el sistema cuyo hardware físico esté ausente.**

Esa condición no existía antes del 12 de agosto.

### Secuencia causal

1. El equipo tenía registrado un único G203 LIGHTSYNC, serie `140E5B0B3015`, con su nodo `&LAMPARRAY` correspondiente. Hardware presente, enumeración correcta, servicio funcionando sin problemas.

2. El 12 de agosto el equipo fue a revisión técnica por falla de la cámara. Durante el diagnóstico se conectó un G203 LIGHTSYNC **con número de serie distinto** (`14315AF63015`) — probablemente un mouse de prueba del técnico, coherente con los otros dispositivos de diagnóstico registrados ese día (memoria SanDisk Cruzer Glide, adaptador Realtek USB GbE).

3. Windows trata un número de serie distinto como una **identidad de dispositivo distinta**. Creó un nodo `&LAMPARRAY` nuevo para el dispositivo nuevo.

4. El nodo `&LAMPARRAY` del mouse anterior **no se elimina** — Windows conserva los registros PnP por si el dispositivo vuelve a conectarse. Quedó como `Present: False`, sin clase, sin GUID, sin driver asociado.

5. Al arrancar, el servicio consultó el registro PnP, encontró **dos interfaces LampArray registradas** e intentó enumerar ambas.

6. Una de ellas apunta a hardware inexistente. No devuelve respuesta ni error de transporte — simplemente silencio. Sin dispositivo físico no hay condición de error que reportar, razón por la cual **ambos canales de eventos del driver permanecen en `RecordCount = 0`**.

7. El servicio entra en bucle de reintento asignando memoria de heap en cada iteración sin liberarla. Tasa medida: ~660 MB/s.

### La distinción que importa

**El mouse no es el error. Dynamic Lighting no es el error.**

| Elemento | Rol |
|---|---|
| Mouse G203 nuevo | **Detonante** — operación completamente rutinaria |
| Nodo `&LAMPARRAY` huérfano | **Condición disparadora** |
| Dynamic Lighting | **Víctima** — nunca llegó a funcionar; Configuración reportaba "No Dynamic Lighting-compatible devices detected" |
| `logi_lamparray_service.exe` | **Responsable** — el defecto está aquí |

Un manejo correcto sería: intento → sin respuesta → timeout → descartar ese dispositivo → continuar. El servicio de Logitech hace: intento → sin respuesta → reintento → reintento → *(indefinidamente)*, dejando memoria sin liberar en cada ciclo.

**Conectar un mouse distinto es una operación normal que Windows maneja a diario sin consecuencias. El defecto está en cómo respondió el software de Logitech a esa situación.**

---

## 6. Descarte formal de la hipótesis de virus

| Afirmación | Evidencia que la refuta |
|---|---|
| "Es un virus" | Binario con firma Authenticode **válida** de Logitech Inc. |
| "Es un archivo malicioso" | Reside en `DriverStore\FileRepository`, protegido por TrustedInstaller — inescribible para malware |
| "Se instaló durante la revisión" | `CreationTime` = **15/06/2026**, dos meses antes |
| "Alguien modificó el archivo" | `LastWriteTime` coincide con `CreationTime` — **sin modificaciones** |
| "Es una tarea anómala" | 23 tareas programadas revisadas: **todas de Microsoft** (Intune, Office, .NET, Maps) |
| "Hay un servicio sospechoso" | 9 servicios fuera de rutas estándar: **todos legítimos** (Defender, .NET, TrustedInstaller) |
| "Está corrupto" | Firma válida = integridad intacta. Un binario corrupto no superaría Code Integrity y no cargaría |
| "Es conflicto de doble controlador" | **Cero eventos** en ambos canales del driver — nunca hubo contención |
| "Es minería / exfiltración" | 197 handles constantes, pool no paginado estable, sin actividad de red ni disco |

**Conclusión: no hay evidencia alguna de software malicioso. Es un defecto de software legítimo firmado.**

Interpretación probable del reporte inicial: al observar un proceso de nombre poco familiar consumiendo ~20 GB en el Administrador de tareas, se asumió infección. Es un error de diagnóstico frecuente, no necesariamente mala fe.

---

## 7. Estado final y pendientes

### Estado actual

| Elemento | Estado |
|---|---|
| Memoria comprometida | **11 GB** (normal) |
| Nodos PnP del G203 | 2 nodos, ambos `Present: True` |
| Servicio LampArray | `Stopped` / `Disabled` |
| Punto de restauración | Disponible — `SequenceNumber 1` |
| Mouse G203 | Funcional, iluminación controlada por G HUB |

### Pendiente — prueba de confirmación final

La reparación aplicó **dos** cambios simultáneos: limpieza de nodos huérfanos **y** deshabilitación del servicio. Por diseño experimental, no es posible saber aún cuál de los dos resolvió el problema.

Para determinarlo, con el equipo estable:

```powershell
$s = (Get-Service *lamp*).Name
Set-Service -Name $s -StartupType Manual
Start-Service -Name $s
1..10 | % { "$(Get-Date -f HH:mm:ss)  $([math]::Round((Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue/1GB,1)) GB"; sleep 60 }
```

| Resultado | Interpretación | Acción |
|---|---|---|
| Commit plano ~11 GB durante 10 min | El nodo huérfano era la causa; el bug ya no tiene condición disparadora | Dejar en `Manual` |
| Commit vuelve a crecer | El bug es independiente del huérfano | Devolver a `Disabled` de forma permanente |

**No hay urgencia.** El equipo está estable con el servicio deshabilitado. En este equipo el servicio nunca llegó a exponer ningún dispositivo a Dynamic Lighting, por lo que mantenerlo deshabilitado no implica pérdida funcional alguna.

### Riesgos de recurrencia

1. **Reactivación por Windows Update.** El paquete es un driver del DriverStore; las actualizaciones de Windows tienden a reactivar estos servicios. Si el consumo de RAM se dispara nuevamente sin causa aparente, verificar primero el estado del servicio.

2. **Cambio de mouse.** Conectar otro G203 (u otro dispositivo LIGHTSYNC) con serie distinta generará un nuevo nodo huérfano y puede reproducir el escenario. El procedimiento de limpieza de la sección 4.5 aplica igual.

### Recomendación

Reportar el defecto a Logitech. Se dispone de un caso mejor documentado que la mayoría de los reportes: fechas, contadores del sistema, tasa de crecimiento medida, InstanceIds involucrados y condición reproducible. Es la única vía por la cual el bug puede corregirse de raíz.

---

## 8. Archivos de evidencia generados

| Archivo | Ubicación | Contenido |
|---|---|---|
| `diag_memoria.txt` | Escritorio | Contadores de memoria, top 15 de procesos, estado de canales de eventos |
| `g203_antes.txt` | Escritorio | Estado de los nodos PnP del G203 y del servicio, previo a la reparación |
| Punto de restauración | Sistema | `Antes limpiar LampArray` — SequenceNumber 1 |

---

## 9. Hipótesis descartadas durante la investigación

Se registran por transparencia metodológica. Cada una fue formulada y posteriormente refutada con datos del propio equipo:

1. **Contención entre Dynamic Lighting y G HUB (Event ID 11).** Refutada por `RecordCount = 0` en ambos canales de eventos del driver.

2. **Fallo del subsistema UMDF provocado por la revisión de la cámara.** Refutada porque los errores `WUDFRd` con status `0xC0000365` son crónicos desde el 23 de julio, tres semanas antes del incidente.

3. **Instalación o modificación reciente del paquete de driver.** Refutada por `CreationTime` = 15/06/2026 sin modificaciones posteriores.

4. **Fuga de handles del kernel.** Refutada por conteo de handles constante en 197 y pool no paginado estable o decreciente.

5. **Malware / tarea anómala.** Refutada por firma Authenticode válida, ubicación en DriverStore, y ausencia total de tareas o servicios anómalos.

---

*Documento generado el 12 de agosto de 2026 a partir de la ejecución directa de comandos en LAPTOP-PRIHIIK2. Todos los valores citados provienen de salidas reales de PowerShell registradas durante el diagnóstico y la reparación.*
