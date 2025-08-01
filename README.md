# 🕵️ GhostHunter

**GhostHunter** es una herramienta desarrollada en PowerShell con una interfaz gráfica moderna (WinForms), diseñada para detectar, analizar y eliminar perfiles de usuario antiguos o huérfanos en equipos Windows. Es útil para tareas de limpieza, mantenimiento de equipos en dominio, y control de perfiles obsoletos en entornos corporativos o sanitarios.

---

## 🚀 Características principales

- ✅ Interfaz gráfica WinForms con diseño profesional.
- 🔍 Escaneo local o remoto del equipo especificado.
- 🧠 Clasificación automática de perfiles:
  - **Activo**: uso reciente o tamaño normal.
  - **Antiguo**: sin modificación en >90 días.
  - **Eliminable**: tamaño inferior a 0.5MB.
- 📋 Visualización de perfiles en ListView con colores por estado.
- ☑️ Selección por checkboxes y eliminación masiva.
- 🔐 Elimina claves del registro (ProfileList) y carpetas físicas.
- 🧹 Usa técnicas agresivas para eliminar perfiles bloqueados, o los marca para borrado al reinicio.
- 📤 Exporta resultados a CSV.
- 📝 Genera informes detallados en TXT.

---

## 🛠️ Requisitos

- PowerShell 5.1 (recomendado)
- Sistema operativo: Windows 10/11 o Windows Server (2016+)
- Permisos de administrador en el equipo local o remoto
- Acceso remoto habilitado a `C$` y al registro remoto del equipo objetivo

---

## 📦 Estructura del Script

El código está organizado en bloques claros y comentados:

- `FUNCIONES DE ANÁLISIS`: lee perfiles desde el registro y calcula tamaño/fecha.
- `INTERFAZ GRÁFICA`: diseño WinForms con campos, botones, filtros y lista.
- `ELIMINACIÓN`: renombrado, borrado forzado o pospuesto tras reinicio.
- `EXPORTACIÓN`: a CSV o informe TXT con resumen completo.
- `FILTROS`: permite visualizar solo perfiles antiguos o eliminables.

---

## 🧪 Cómo usar GhostHunter

1. Ejecuta el script como **administrador**.
2. Introduce el nombre del equipo local o remoto.
3. Pulsa **Escanear**.
4. Marca los perfiles a eliminar o usa los filtros.
5. Pulsa **Eliminar perfiles marcados**.
6. (Opcional) Exporta resultados o genera un informe.

---

## 🧠 Lógica de Clasificación

| Estado                | Criterio                                              |
|-----------------------|--------------------------------------------------------|
| Activo                | Última modificación reciente y tamaño normal           |
| Antiguo               | Última modificación hace más de 90 días                |
| Eliminable (<0.5MB)   | Tamaño del perfil menor a 0.5 MB                       |

---

## 🔐 Seguridad

GhostHunter no borra directamente perfiles activos ni modifica cuentas en uso. Toda operación:
- Requiere confirmación explícita.
- Registra errores y los notifica al usuario.
- Incluye múltiples capas de verificación (acceso UNC, claves del registro, etc.).

---

## 🧩 Limitaciones

- No detecta perfiles almacenados en rutas no estándar.
- Si el equipo remoto no permite acceso a `C$` o al registro, mostrará advertencias.
- Algunas carpetas solo pueden eliminarse tras reinicio por bloqueo de archivos.

---

## 📘 Licencia

Este proyecto está publicado bajo la **MIT License**. Puedes modificar, reutilizar y distribuir libremente.

---

## 🙋‍♂️ Autor

Desarrollado por **Sergio**, Técnico N2 para el SERGAS, con enfoque práctico y profesional para entornos corporativos.

---
