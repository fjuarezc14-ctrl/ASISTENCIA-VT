-- ==========================================================
-- SCRIPT DE INICIALIZACIÓN - SISTEMA ASISTENCIA VT VALETEC
-- 100% SEGURO Y NO DESTRUCTIVO: IF NOT EXISTS
-- ==========================================================

-- 1. Tabla de Empleados
CREATE TABLE IF NOT EXISTS empleados (
    id SERIAL PRIMARY KEY,
    nombre_completo VARCHAR(150) NOT NULL,
    codigo_pin VARCHAR(100) NOT NULL,
    face_descriptor JSONB NOT NULL,
    area VARCHAR(100) DEFAULT 'Desarrollo de Software',
    dias_laborables VARCHAR(150) DEFAULT 'Lun, Mar, Mié, Jue, Vie, Sáb',
    hora_ingreso VARCHAR(10) DEFAULT '08:00',
    hora_salida VARCHAR(10) DEFAULT '18:00',
    hora_ingreso_sab VARCHAR(10) DEFAULT '08:00',
    hora_salida_sab VARCHAR(10) DEFAULT '13:00',
    inicio_refrigerio VARCHAR(10) DEFAULT '13:00',
    fin_refrigerio VARCHAR(10) DEFAULT '15:00',
    activo BOOLEAN DEFAULT TRUE,
    creado_en TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla de Registros de Asistencia
CREATE TABLE IF NOT EXISTS registros_asistencia (
    id SERIAL PRIMARY KEY,
    empleado_id INTEGER REFERENCES empleados(id) ON DELETE CASCADE,
    metodo VARCHAR(50) NOT NULL,
    tipo VARCHAR(50) NOT NULL,
    horas_trabajadas VARCHAR(50),
    minutos_netos INTEGER,
    fecha_hora_marcacion TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Índices de Rendimiento para Reportes y Consultas
CREATE INDEX IF NOT EXISTS idx_asistencia_empleado_fecha 
    ON registros_asistencia(empleado_id, fecha_hora_marcacion DESC);

CREATE INDEX IF NOT EXISTS idx_asistencia_fecha 
    ON registros_asistencia(fecha_hora_marcacion DESC);

CREATE INDEX IF NOT EXISTS idx_empleados_activo 
    ON empleados(activo);

-- 4. Tabla de Justificaciones, Tolerancias y Permisos Gerenciales
CREATE TABLE IF NOT EXISTS justificaciones_asistencia (
    id SERIAL PRIMARY KEY,
    empleado_id INTEGER REFERENCES empleados(id) ON DELETE CASCADE,
    asistencia_id INTEGER REFERENCES registros_asistencia(id) ON DELETE CASCADE,
    fecha DATE NOT NULL,
    tipo VARCHAR(50) NOT NULL, -- 'TARDANZA_JUSTIFICADA', 'TOLERANCIA_PREVIA', 'PERMISO_DIA', 'VACACIONES'
    hora_tolerancia VARCHAR(10), -- Ej: '09:30' (opcional si es tolerancia previa)
    motivo VARCHAR(255) DEFAULT 'Autorizado por Gerencia',
    autorizado_por VARCHAR(100) DEFAULT 'Gerencia',
    creado_en TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_justif_empleado_fecha 
    ON justificaciones_asistencia(empleado_id, fecha);

CREATE INDEX IF NOT EXISTS idx_justif_asistencia 
    ON justificaciones_asistencia(asistencia_id);

-- 5. Tabla de Documentos y Expedientes de Empleados
CREATE TABLE IF NOT EXISTS documentos_empleado (
    id SERIAL PRIMARY KEY,
    empleado_id INTEGER REFERENCES empleados(id) ON DELETE CASCADE,
    tipo_documento VARCHAR(50) NOT NULL, -- 'CV', 'DNI', 'RECIBO_SERVICIOS', 'CONTRATO', 'OTRO'
    nombre_archivo VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    tamano_bytes INTEGER NOT NULL,
    archivo_base64 TEXT NOT NULL,
    subido_por VARCHAR(100) DEFAULT 'Gerencia',
    subido_en TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_docs_empleado 
    ON documentos_empleado(empleado_id);
