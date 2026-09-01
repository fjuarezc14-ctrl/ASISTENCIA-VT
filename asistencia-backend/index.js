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

// Endpoint 2: Guardar asistencia (CON AUTO-SALIDA A LAS 8:00 PM)
app.post('/api/asistencia', async (req, res) => {
  const { empleado_id, metodo } = req.body; 
  
  try {
    const lastMarkQuery = `
      SELECT tipo, fecha_hora_marcacion 
      FROM registros_asistencia 
      WHERE empleado_id = $1 
      ORDER BY fecha_hora_marcacion DESC LIMIT 1
    `;
    const lastMarkResult = await db.query(lastMarkQuery, [empleado_id]);

    let tipoAsistencia = 'INGRESO';
    let mensajeExtra = '';

    if (lastMarkResult.rows.length > 0) {
      const ultimaMarcacion = lastMarkResult.rows[0];
      const fechaUltima = new Date(ultimaMarcacion.fecha_hora_marcacion);
      const ahora = new Date();
      
      // 1. Validar Anti-Doble Clic (Bloqueo de 3 minutos)
      const diferenciaMinutos = (ahora - fechaUltima) / (1000 * 60);
      if (diferenciaMinutos < 3) {
        return res.status(429).json({ 
          error: 'Acabas de registrar asistencia. Espera unos minutos antes de volver a marcar.' 
        });
      }

      // 2. Lógica de Cambio de Estado y Días
      const esMismoDia = fechaUltima.toDateString() === ahora.toDateString();

      if (esMismoDia) {
        // Mismo día: Alternamos entre INGRESO y SALIDA
        tipoAsistencia = (ultimaMarcacion.tipo === 'INGRESO') ? 'SALIDA' : 'INGRESO';
      } else {
        // Día diferente: Revisamos si dejó el turno de ayer sin cerrar
        if (ultimaMarcacion.tipo === 'INGRESO') {
          
          // --- AUTO-CIERRE A LAS 8:00 PM DEL DÍA DEL INGRESO ---
          const fechaSalidaAutomatica = new Date(ultimaMarcacion.fecha_hora_marcacion);
          fechaSalidaAutomatica.setHours(20, 0, 0, 0); // 20:00:00 = 8:00 PM local
          
          // Insertamos la salida faltante obligando a la base de datos a usar la fecha/hora de ayer
          const autoSalidaQuery = `
            INSERT INTO registros_asistencia (empleado_id, metodo, tipo, fecha_hora_marcacion) 
            VALUES ($1, $2, $3, $4)
          `;
          // Le ponemos 'SISTEMA_AUTO' en el método para que en el reporte sepan que no fue el empleado
          await db.query(autoSalidaQuery, [empleado_id, 'SISTEMA_AUTO', 'SALIDA', fechaSalidaAutomatica]);
          
          mensajeExtra = ' (Aviso: El sistema cerró tu turno anterior a las 8:00 PM por omisión)';
        }
        
        // Empieza su nuevo día
        tipoAsistencia = 'INGRESO'; 
      }
    }

    // 3. Insertar el registro actual (el que el empleado está haciendo hoy/ahora)
    const insertQuery = 'INSERT INTO registros_asistencia (empleado_id, metodo, tipo) VALUES ($1, $2, $3) RETURNING id, fecha_hora_marcacion';
    const result = await db.query(insertQuery, [empleado_id, (metodo || 'DESCONOCIDO').toUpperCase(), tipoAsistencia]);
    const nuevaMarcacion = result.rows[0];

    const empResult = await db.query('SELECT nombre_completo FROM empleados WHERE id = $1', [empleado_id]);
    const nombre = empResult.rows[0]?.nombre_completo || 'Desconocido';

    console.log(`✅ ${tipoAsistencia}: ${nombre} (${metodo}) - ${nuevaMarcacion.fecha_hora_marcacion.toLocaleTimeString('es-ES')}`);
    
    res.status(201).json({ 
      success: true, 
      mensaje: `Asistencia de ${tipoAsistencia} registrada${mensajeExtra}`, 
      nombre: nombre,
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
