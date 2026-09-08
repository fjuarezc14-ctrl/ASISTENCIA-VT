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
    activo BOOLEAN DEFAULT TRUE,
    creado_en TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla de Registros de Asistencia
CREATE TABLE IF NOT EXISTS registros_asistencia (
    id SERIAL PRIMARY KEY,
    empleado_id INTEGER REFERENCES empleados(id) ON DELETE CASCADE,
    metodo VARCHAR(50) NOT NULL,
    tipo VARCHAR(50) NOT NULL,
    fecha_hora_marcacion TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Índices de Rendimiento para Reportes y Consultas
CREATE INDEX IF NOT EXISTS idx_asistencia_empleado_fecha 
    ON registros_asistencia(empleado_id, fecha_hora_marcacion DESC);

CREATE INDEX IF NOT EXISTS idx_asistencia_fecha 
    ON registros_asistencia(fecha_hora_marcacion DESC);

CREATE INDEX IF NOT EXISTS idx_empleados_activo 
    ON empleados(activo);
