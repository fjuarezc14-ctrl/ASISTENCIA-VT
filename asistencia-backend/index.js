const express = require('express');
const cors = require('cors');
const db = require('./db');
require('dotenv').config();

// 1. PRIMERO inicializamos la aplicación 'app'
const app = express();
const PORT = process.env.PORT || 3008;

// 2. LUEGO definimos las opciones de CORS estricto
const corsOptions = {
    origin: 'https://registro.valetec.pe', // Dominio exacto de tu frontend sin '/' al final
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

// 3. APLICAMOS el CORS estricto y el lector de JSON
app.use(cors(corsOptions));
app.use(express.json());

// Endpoint 1: Obtener empleados
app.get('/api/empleados', async (req, res) => {
  try {
    const result = await db.query('SELECT id, nombre_completo, codigo_pin, face_descriptor FROM empleados WHERE activo = TRUE');
    res.json(result.rows);
  } catch (err) {
    console.error('Error GET empleados:', err);
    res.status(500).json({ error: 'Error al obtener empleados' });
  }
});

// Endpoint 3: Crear nuevo empleado (Para el Panel de Admin)
app.post('/api/empleados', async (req, res) => {
  const { nombre_completo, codigo_pin, face_descriptor } = req.body;

  // Validar que lleguen todos los datos
  if (!nombre_completo || !codigo_pin || !face_descriptor) {
    return res.status(400).json({ error: 'Faltan datos obligatorios (nombre, pin o rostro).' });
  }

  try {
    const query = `
      INSERT INTO empleados (nombre_completo, codigo_pin, face_descriptor) 
      VALUES ($1, $2, $3) 
      RETURNING id, nombre_completo
    `;
    
    // face_descriptor debe llegar como un array (lista de números) desde el frontend
    // Postgres lo guardará automáticamente como JSONB
    const result = await db.query(query, [nombre_completo, codigo_pin, JSON.stringify(face_descriptor)]);
    const nuevoEmpleado = result.rows[0];

    console.log(`👤 Nuevo empleado registrado: ${nuevoEmpleado.nombre_completo} (ID: ${nuevoEmpleado.id})`);
    res.status(201).json({ success: true, mensaje: 'Empleado registrado con éxito', empleado: nuevoEmpleado });

  } catch (err) {
    console.error('Error POST empleados (Crear):', err);
    res.status(500).json({ error: 'Error interno al crear el empleado' });
  }
});

// Endpoint 2: Guardar asistencia (LÓGICA ESTRICTA INGRESO/SALIDA)
app.post('/api/asistencia', async (req, res) => {
  const { empleado_id, metodo, tipo } = req.body; 
  
  try {
    const lastMarkQuery = `
      SELECT tipo, fecha_hora_marcacion 
      FROM registros_asistencia 
      WHERE empleado_id = $1 
      ORDER BY fecha_hora_marcacion DESC LIMIT 1
    `;
    const lastMarkResult = await db.query(lastMarkQuery, [empleado_id]);

    let tipoAsistencia = tipo ? tipo.toUpperCase() : null;
    let mensajeExtra = '';

    if (lastMarkResult.rows.length > 0) {
      const ultimaMarcacion = lastMarkResult.rows[0];
      const fechaUltima = new Date(ultimaMarcacion.fecha_hora_marcacion);
      const ahora = new Date();
      
      // Ajuste al reloj de Perú (UTC -5)
      const fechaUltimaPeru = new Date(fechaUltima.getTime() - (5 * 60 * 60 * 1000));
      const ahoraPeru = new Date(ahora.getTime() - (5 * 60 * 60 * 1000));
      const esMismoDia = fechaUltimaPeru.getUTCFullYear() === ahoraPeru.getUTCFullYear() && 
                         fechaUltimaPeru.getUTCMonth() === ahoraPeru.getUTCMonth() && 
                         fechaUltimaPeru.getUTCDate() === ahoraPeru.getUTCDate();

      // 1. NUEVA LÓGICA DE BLOQUEO POR ESTADO (Reemplaza los 3 minutos de espera)
      // Si es el mismo día y el trabajador intenta marcar la misma acción que ya hizo:
      if (esMismoDia && tipoAsistencia === ultimaMarcacion.tipo) {
        const accionCorrecta = ultimaMarcacion.tipo === 'INGRESO' ? 'SALIDA' : 'INGRESO';
        return res.status(400).json({ 
            error: `Usted ya marcó ${ultimaMarcacion.tipo}. Por favor, marque ${accionCorrecta}.` 
        });
      }

      // Fallback: Si el frontend no envía 'tipo' por alguna razón
      if (!tipoAsistencia) {
         tipoAsistencia = esMismoDia && ultimaMarcacion.tipo === 'INGRESO' ? 'SALIDA' : 'INGRESO';
      }

      // 2. Auto-Cierre: Si inicia un nuevo día y olvidó marcar salida ayer
      if (!esMismoDia && ultimaMarcacion.tipo === 'INGRESO' && tipoAsistencia === 'INGRESO') {
          const fechaSalidaAutomatica = new Date(fechaUltima);
          fechaSalidaAutomatica.setHours(20, 0, 0, 0); // 8:00 PM del día anterior
          
          const autoSalidaQuery = `INSERT INTO registros_asistencia (empleado_id, metodo, tipo, fecha_hora_marcacion) VALUES ($1, $2, $3, $4)`;
          await db.query(autoSalidaQuery, [empleado_id, 'SISTEMA_AUTO', 'SALIDA', fechaSalidaAutomatica]);
          mensajeExtra = ' (Aviso: El sistema cerró tu turno de ayer por omisión)';
      }
    } else if (!tipoAsistencia) {
      tipoAsistencia = 'INGRESO'; // Primer registro de su vida
    }

    // 3. Insertar el registro actual
    const insertQuery = 'INSERT INTO registros_asistencia (empleado_id, metodo, tipo) VALUES ($1, $2, $3) RETURNING id, fecha_hora_marcacion';
    const result = await db.query(insertQuery, [empleado_id, (metodo || 'DESCONOCIDO').toUpperCase(), tipoAsistencia]);
    
    const empResult = await db.query('SELECT nombre_completo FROM empleados WHERE id = $1', [empleado_id]);
    res.status(201).json({ 
      success: true, 
      mensaje: `Asistencia de ${tipoAsistencia} registrada${mensajeExtra}`, 
      nombre: empResult.rows[0]?.nombre_completo || 'Desconocido',
      tipo: tipoAsistencia 
    });

  } catch (err) {
    console.error('Error POST asistencia:', err);
    res.status(500).json({ error: 'Error interno al registrar la asistencia' });
  }
});

// Endpoint 4: Ver Reportes (AHORA CON FILTROS INTELIGENTES)
app.get('/api/reportes', async (req, res) => {
  const { empleado_id, periodo } = req.query;

  try {
    let query = `
      SELECT r.id, e.nombre_completo, r.fecha_hora_marcacion, r.metodo, r.tipo
      FROM registros_asistencia r
      JOIN empleados e ON r.empleado_id = e.id
      WHERE 1=1
    `;
    const values = [];

    // 1. Filtro por Trabajador
    if (empleado_id && empleado_id !== 'TODOS') {
      values.push(empleado_id);
      query += ` AND r.empleado_id = $${values.length}`;
    }

    // 2. Filtro por Tiempo (Día, Semana, Mes)
    if (periodo === 'DIA') {
      query += ` AND DATE(r.fecha_hora_marcacion) = CURRENT_DATE`;
    } else if (periodo === 'SEMANA') {
      query += ` AND r.fecha_hora_marcacion >= date_trunc('week', CURRENT_DATE)`;
    } else if (periodo === 'MES') {
      query += ` AND r.fecha_hora_marcacion >= date_trunc('month', CURRENT_DATE)`;
    }

    // Ordenar siempre del más reciente al más antiguo
    query += ` ORDER BY r.fecha_hora_marcacion DESC LIMIT 500;`;

    const result = await db.query(query, values);
    res.json(result.rows);
  } catch (err) {
    console.error('Error GET reportes:', err);
    res.status(500).json({ error: 'Error al obtener reportes filtrados' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en: http://localhost:${PORT}`);
});
