const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

async function inicializarEsquema() {
  try {
    // 1. Columnas adicionales para empleados si ya existía la tabla previa
    await pool.query(`
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS area VARCHAR(100) DEFAULT 'Desarrollo de Software';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS dias_laborables VARCHAR(150) DEFAULT 'Lun, Mar, Mié, Jue, Vie, Sáb';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS hora_ingreso VARCHAR(10) DEFAULT '08:00';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS hora_salida VARCHAR(10) DEFAULT '18:00';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS hora_ingreso_sab VARCHAR(10) DEFAULT '08:00';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS hora_salida_sab VARCHAR(10) DEFAULT '13:00';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS inicio_refrigerio VARCHAR(10) DEFAULT '13:00';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS fin_refrigerio VARCHAR(10) DEFAULT '15:00';
      ALTER TABLE empleados ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT TRUE;
      ALTER TABLE empleados ALTER COLUMN codigo_pin TYPE VARCHAR(255) USING codigo_pin::varchar;
    `);

    // 2. Columnas adicionales para registros_asistencia
    await pool.query(`
      ALTER TABLE registros_asistencia ADD COLUMN IF NOT EXISTS horas_trabajadas VARCHAR(50);
      ALTER TABLE registros_asistencia ADD COLUMN IF NOT EXISTS minutos_netos INTEGER;
    `);

    // 3. Tablas nuevas si no existían previamente
    await pool.query(`
      CREATE TABLE IF NOT EXISTS justificaciones_asistencia (
          id SERIAL PRIMARY KEY,
          empleado_id INTEGER REFERENCES empleados(id) ON DELETE CASCADE,
          asistencia_id INTEGER REFERENCES registros_asistencia(id) ON DELETE CASCADE,
          fecha DATE NOT NULL,
          tipo VARCHAR(50) NOT NULL,
          hora_tolerancia VARCHAR(10),
          motivo VARCHAR(255) DEFAULT 'Autorizado por Gerencia',
          autorizado_por VARCHAR(100) DEFAULT 'Gerencia',
          creado_en TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS documentos_empleado (
          id SERIAL PRIMARY KEY,
          empleado_id INTEGER REFERENCES empleados(id) ON DELETE CASCADE,
          tipo_documento VARCHAR(50) NOT NULL,
          nombre_archivo VARCHAR(255) NOT NULL,
          mime_type VARCHAR(100) NOT NULL,
          tamano_bytes INTEGER NOT NULL,
          archivo_base64 TEXT NOT NULL,
          subido_por VARCHAR(100) DEFAULT 'Gerencia',
          subido_en TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_asistencia_empleado_fecha ON registros_asistencia(empleado_id, fecha_hora_marcacion DESC);
      CREATE INDEX IF NOT EXISTS idx_asistencia_fecha ON registros_asistencia(fecha_hora_marcacion DESC);
      CREATE INDEX IF NOT EXISTS idx_empleados_activo ON empleados(activo);
      CREATE INDEX IF NOT EXISTS idx_justif_empleado_fecha ON justificaciones_asistencia(empleado_id, fecha);
      CREATE INDEX IF NOT EXISTS idx_justif_asistencia ON justificaciones_asistencia(asistencia_id);
      CREATE INDEX IF NOT EXISTS idx_docs_empleado ON documentos_empleado(empleado_id);
    `);
    console.log('✅ Esquema y migraciones de PostgreSQL verificadas con éxito (100% no destructivo).');
  } catch (err) {
    console.error('⚠️ Error al verificar/migrar esquema en PostgreSQL:', err.message);
  }
}

pool.connect(async (err, client, release) => {
  if (err) {
    return console.error('❌ Error de conexión a Postgres:', err.stack);
  }
  console.log('✅ Conexión exitosa a PostgreSQL establecida.');
  release();
  await inicializarEsquema();
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};