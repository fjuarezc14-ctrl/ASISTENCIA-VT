# 🏢 ASISTENCIA-VT — Sistema Biométrico de Control de Asistencia
> **Desarrollado para VALETEC**  
> Control de asistencia corporativo con reconocimiento facial multi-descriptor asistido por IA (`face-api.js`), marcación por PIN seguro (`bcrypt`), panel de administración y reportes gerenciales con exportación a Excel/PDF e infraestructura contenerizada en Docker.

---

## 📑 Tabla de Contenidos
1. [Arquitectura del Sistema](#-arquitectura-del-sistema)
2. [Asignación de Puertos y Aislamiento](#-asignación-de-puertos-y-aislamiento)
3. [Seguridad y Blindaje de Vulnerabilidades](#-seguridad-y-blindaje-de-vulnerabilidades)
4. [Guía de Despliegue con Docker en Producción](#-guía-de-despliegue-con-docker-en-producción)
5. [Configuración de Variables de Entorno](#-configuración-de-variables-de-entorno)
6. [Lógica de Negocio y Reglas Operativas](#-lógica-de-negocio-y-reglas-operativas)
7. [Mantenimiento y Respaldo de Base de Datos](#-mantenimiento-y-respaldo-de-base-de-datos)
8. [Estructura del Proyecto](#-estructura-del-proyecto)

---

## 🏛 Arquitectura del Sistema

El sistema opera bajo una arquitectura multi-contenedor orquestada mediante Docker Compose:

```
                  +-----------------------------------+
                  |        Nginx Reverse Proxy        |
                  |  (registro.valetec.pe / SSL)      |
                  +-----------------+-----------------+
                                    |
            +-----------------------+-----------------------+
            | :3007                                         | :3008 (/api)
  +---------v----------------+                     +--------v----------------+
  |   asistencia-frontend    |                     |   asistencia-backend    |
  |     (Nginx Alpine)       |                     |   (Node.js 20 Express)  |
  | - index.html (Terminal)  |                     | - Auth JWT Admin        |
  | - admin.html (Personal)  |                     | - Bcrypt PIN Validation |
  | - reportes.html (Auditor)|                     | - Face Descriptors Proc |
  +--------------------------+                     +--------+----------------+
                                                            |
                                                            | :5432 (Host 5438)
                                                   +--------v----------------+
                                                   |      asistencia-db      |
                                                   | (PostgreSQL 16 Alpine)  |
                                                   | Volume: ./postgres-data |
                                                   +-------------------------+
```

---

## 🔌 Asignación de Puertos y Aislamiento

Para garantizar convivencia sin colisiones con los demás proyectos del servidor host (como *Fogón Dorado*, *Taller Vargas*, *Glowmanager*, *Valeventas*, etc.), los puertos asignados son:

| Servicio | Contenedor | Puerto Host | Puerto Interno | Descripción |
| :--- | :--- | :---: | :---: | :--- |
| **Frontend Web** | `asistencia-frontend` | `3007` | `80` | Servidor Nginx que distribuye las vistas HTML y proxifica `/api/` |
| **Backend API** | `asistencia-backend` | `3008` | `3008` | API REST en Node.js 20 con Express y conexión a PostgreSQL |
| **Base de Datos** | `asistencia-db` | `5438` | `5432` | PostgreSQL 16 con volumen persistente montado en `./postgres-data` |

---

## 🛡 Seguridad y Blindaje de Vulnerabilidades

El sistema ha sido auditado y blindado contra vulnerabilidades críticas:

1. **Protección de Credenciales (VULN-01):**
   - El endpoint público `/api/empleados` **excluye de forma permanente** la columna `codigo_pin`. Ningún PIN viaja hacia el cliente en las respuestas del navegador.
2. **Validación Estricta de PIN en el Servidor (VULN-02):**
   - El PIN se valida exclusivamente en el backend (`POST /api/asistencia/pin`).
   - Los PINs se almacenan hasheados con algoritmo criptográfico `bcryptjs` con salt de factor 10.
3. **Control de Acceso Administrativo con JWT (VULN-03):**
   - Se requiere un token JWT (`Authorization: Bearer <token>`) para acceder a la creación de empleados, activación/desactivación y reportería de asistencias.
   - Las interfaces `admin.html` y `reportes.html` bloquean el acceso mediante un modal de inicio de sesión seguro y persistencia local del token.

---

## 🚀 Guía de Despliegue con Docker en Producción

### 1. Requisitos Previos
- Servidor Linux con Docker y Docker Compose instalados (`docker compose version` >= 2.0).
- Git instalado.

### 2. Clonar el Repositorio
```bash
cd /opt
git clone https://github.com/fjuarezc14-ctrl/ASISTENCIA-VT.git
cd ASISTENCIA-VT
```

### 3. Crear el Archivo de Entorno (`.env`)
Copie la plantilla y configure contraseñas seguras para producción:
```bash
cp .env.example .env
nano .env
```

Ejemplo de `.env` para producción:
```ini
DB_USER=postgres
DB_PASSWORD=SuPasswordSeguroPostgres2026!
DB_NAME=vt_asistencia
DB_PORT=5438

BACKEND_PORT=3008
FRONTEND_PORT=3007

JWT_SECRET=super_clave_secreta_jwt_valetec_asistencia_2026
ADMIN_USER=admin
ADMIN_PASSWORD=PasswordAdminSeguro2026!
```

### 4. Construir y Levantar los Contenedores
```bash
docker compose up -d --build
```

### 5. Verificar que Todo Esté Activo y Saludable
```bash
docker compose ps
```
Debe observar los tres contenedores (`asistencia-db`, `asistencia-backend`, `asistencia-frontend`) en estado `Up` y `Healthy`.

---

## 🧠 Lógica de Negocio y Reglas Operativas

### A. Reconocimiento Facial Asistido (Multi-Descriptor)
- **Registro de Personal (`admin.html`):** Al dar de alta un trabajador, la cámara toma 3 muestras biométricas sucesivas guiadas visualmente (*Frente*, *Gesto/Sonrisa*, *Ángulo sutil*). Se guardan 3 vectores de 128 dimensiones en PostgreSQL.
- **Terminal de Marcación (`index.html`):**
  - Umbral de distancia euclidiana calibrado a `0.48`: **Cero falsos positivos** (imposible que confunda a un compañero con otro).
  - **Filtro Anti-Flicker:** Requiere confirmación de 2 lecturas consecutivas (aprox. 500 ms) antes de registrar la marcación.
  - Cámara en orientación natural (sin modo espejo).

### B. Ciclo Diario y Prevención de Errores de Marcación
- **Protección de Primer Registro del Día:** En un nuevo día, el sistema **bloquea cualquier intento de marcar SALIDA** si el colaborador no registra un ingreso previo hoy.
- **Reset de Madrugada (04:00 AM):** La terminal no fuerza cambios a `INGRESO` durante la tarde para permitir que todo el personal marque su salida en fila sin fricciones. A las **04:00 AM**, un vigilante interno resetea automáticamente la terminal a `INGRESO` y recarga la lista de empleados para la nueva jornada.
- **Auto-Cierre de Turnos Anteriores por Omisión:** Si un colaborador salió a campo o ventas y no regresó a marcar su salida ayer: al llegar hoy a marcar su `INGRESO`, el sistema inserta automáticamente la `SALIDA` de ayer a las 20:00 (etiquetada como `SISTEMA_AUTO`) y registra hoy su `INGRESO` sin bloquearlo.
- **Conmutación Inteligente en Pantalla:** Si la terminal está en `INGRESO` y un trabajador que ya ingresó hoy se para frente a la cámara, el servidor responde sugiriendo `SALIDA` y la pantalla conmuta sola el botón a `SALIDA`.

---

## 💾 Mantenimiento y Respaldo de Base de Datos

Los datos de empleados, asistencias y credenciales residen en el volumen local `./postgres-data`.

### Generar Respaldo Manual de la Base de Datos
```bash
docker exec -t asistencia-db pg_dump -U postgres -d vt_asistencia > backup_asistencia_$(date +%Y%m%d_%H%M%S).sql
```

### Restaurar Respaldo
```bash
cat backup_asistencia.sql | docker exec -i asistencia-db psql -U postgres -d vt_asistencia
```

---

## 📂 Estructura del Proyecto

```
ASISTENCIA-VT/
├── admin.html               # Panel de Gestión: Registro multi-muestra y lista de personal
├── index.html               # Terminal de Marcación: Rostro IA + Teclado PIN en vivo
├── reportes.html            # Auditoría: Métricas hoy, filtros, exportación CSV e impresión PDF
├── nginx.conf               # Configuración de proxy inverso Nginx para el frontend
├── Dockerfile.frontend      # Dockerfile Nginx estático y proxy
├── docker-compose.yml       # Orquestación de BD, Backend y Frontend
├── init.sql                 # Esquema DDL inicial de PostgreSQL (IF NOT EXISTS)
├── manifest.json            # Manifiesto PWA para instalación en tablets/quioscos
├── .env.example             # Plantilla de variables de entorno
├── .gitignore               # Exclusión de node_modules, postgres-data y .env
├── .dockerignore            # Exclusión de archivos pesados en contexto Docker
└── asistencia-backend/
    ├── Dockerfile           # Dockerfile Node.js 20 Alpine
    ├── package.json         # Dependencias: express, pg, bcryptjs, jsonwebtoken, cors, dotenv
    ├── db.js                # Conexión Pool a PostgreSQL
    └── index.js             # API REST con endpoints blindados y lógica de asistencias
```
