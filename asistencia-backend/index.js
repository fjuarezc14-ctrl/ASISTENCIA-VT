const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
require('dotenv').config();

// 1. Inicialización de App y Configuración
const app = express();
const PORT = process.env.PORT || 3008;

const JWT_SECRET = process.env.JWT_SECRET || 'valetec_jwt_secret_asistencia_2026';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Valetec2026!';

// 2. CORS para Producción y Desarrollo
const allowedOrigins = [
    'https://registro.valetec.pe',
    'https://asistencia.valetec.pe',
    'http://localhost:3007',
    'http://localhost:3008',
    'http://127.0.0.1:3007',
    'http://127.0.0.1:3008'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Bloqueado por política CORS'));
        }
    },
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// ==========================================================
// MIDDLEWARE DE AUTENTICACIÓN ADMINISTRATIVA (JWT)
// ==========================================================
function verificarAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Acceso no autorizado. Debe iniciar sesión como administrador.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Token inválido o expirado. Inicie sesión nuevamente.' });
    }
}

// ==========================================================
// RUTAS DE AUTENTICACIÓN ADMINISTRATIVA
// ==========================================================
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña obligatorios' });
    }

    if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
        const token = jwt.sign(
            { role: 'admin', username: ADMIN_USER },
            JWT_SECRET,
            { expiresIn: '12h' }
        );
        return res.json({ 
            success: true, 
            token, 
            username: ADMIN_USER,
            mensaje: 'Inicio de sesión exitoso'
        });
    }

    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
});

app.get('/api/auth/verify', verificarAdmin, (req, res) => {
    res.json({ success: true, admin: req.admin });
});

// ==========================================================
// RUTAS DE EMPLEADOS
// ==========================================================

// Endpoint 1: Obtener empleados para la Terminal de Marcación (SEGURO: SIN PIN)
app.get('/api/empleados', async (req, res) => {
    try {
        // VULN-01 CORREGIDA: Se excluye permanentemente codigo_pin
        const result = await db.query(
            'SELECT id, nombre_completo, face_descriptor FROM empleados WHERE activo = TRUE ORDER BY id ASC'
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error GET empleados:', err);
        res.status(500).json({ error: 'Error al obtener empleados' });
    }
});

// Endpoint 1B: Listar empleados para Panel de Admin (PROTEGIDO)
app.get('/api/empleados/admin', verificarAdmin, async (req, res) => {
    try {
        const query = `
            SELECT e.id, e.nombre_completo, 
                   COALESCE(e.area, 'Desarrollo de Software') AS area,
                   COALESCE(e.dias_laborables, 'Lun, Mar, Mié, Jue, Vie, Sáb') AS dias_laborables,
                   COALESCE(e.hora_ingreso, '08:00') AS hora_ingreso,
                   COALESCE(e.hora_salida, '18:00') AS hora_salida,
                   COALESCE(e.hora_ingreso_sab, '08:00') AS hora_ingreso_sab,
                   COALESCE(e.hora_salida_sab, '13:00') AS hora_salida_sab,
                   COALESCE(e.inicio_refrigerio, '13:00') AS inicio_refrigerio,
                   COALESCE(e.fin_refrigerio, '14:00') AS fin_refrigerio,
                   e.activo, e.creado_en,
                   (e.face_descriptor IS NOT NULL) AS tiene_rostro,
                   COUNT(r.id)::int AS total_asistencias
            FROM empleados e
            LEFT JOIN registros_asistencia r ON e.id = r.empleado_id
            GROUP BY e.id
            ORDER BY e.id DESC
        `;
        const result = await db.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error('Error GET empleados/admin:', err);
        res.status(500).json({ error: 'Error al obtener lista administrativa de empleados' });
    }
});

// Endpoint 1C: Activar / Desactivar empleado (PROTEGIDO)
app.patch('/api/empleados/:id/toggle', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query(
            'UPDATE empleados SET activo = NOT activo WHERE id = $1 RETURNING id, nombre_completo, activo',
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Empleado no encontrado' });
        }
        const empleado = result.rows[0];
        res.json({ 
            success: true, 
            empleado, 
            mensaje: `Empleado ${empleado.activo ? 'activado' : 'desactivado'} con éxito` 
        });
    } catch (err) {
        console.error('Error PATCH empleados toggle:', err);
        res.status(500).json({ error: 'Error al alternar estado del empleado' });
    }
});

// Endpoint 3: Crear nuevo empleado (PROTEGIDO + HASHEO BCRYPT)
app.post('/api/empleados', verificarAdmin, async (req, res) => {
    const { 
        nombre_completo, codigo_pin, face_descriptor, 
        area, dias_laborables, 
        hora_ingreso, hora_salida, 
        hora_ingreso_sab, hora_salida_sab, 
        inicio_refrigerio, fin_refrigerio 
    } = req.body;

    if (!nombre_completo || !codigo_pin || !face_descriptor) {
        return res.status(400).json({ error: 'Faltan datos obligatorios (nombre, pin o rostro).' });
    }

    try {
        // VULN-02 CORREGIDA: Hasheo seguro del PIN con bcrypt antes de guardar
        const salt = await bcrypt.genSalt(10);
        const hashedPin = await bcrypt.hash(codigo_pin.toString(), salt);

        const query = `
            INSERT INTO empleados (
                nombre_completo, codigo_pin, face_descriptor, 
                area, dias_laborables, 
                hora_ingreso, hora_salida, 
                hora_ingreso_sab, hora_salida_sab, 
                inicio_refrigerio, fin_refrigerio
            ) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
            RETURNING id, nombre_completo, area, dias_laborables, hora_ingreso, hora_salida, activo
        `;
        
        const result = await db.query(query, [
            nombre_completo.trim(), 
            hashedPin, 
            JSON.stringify(face_descriptor),
            area || 'Desarrollo de Software',
            dias_laborables || 'Lun, Mar, Mié, Jue, Vie, Sáb',
            hora_ingreso || '08:00',
            hora_salida || '18:00',
            hora_ingreso_sab || '08:00',
            hora_salida_sab || '13:00',
            inicio_refrigerio || '13:00',
            fin_refrigerio || '15:00'
        ]);
        const nuevoEmpleado = result.rows[0];

        console.log(`👤 Nuevo empleado registrado: ${nuevoEmpleado.nombre_completo} (ID: ${nuevoEmpleado.id})`);
        res.status(201).json({ 
            success: true, 
            mensaje: 'Empleado registrado con éxito', 
            empleado: nuevoEmpleado 
        });
    } catch (err) {
        console.error('Error POST empleados (Crear):', err);
        res.status(500).json({ error: 'Error interno al crear el empleado' });
    }
});

// ==========================================================
// ==========================================================
// LÓGICA CENTRAL DE MARCACIÓN (2 ESTADOS: INGRESO / SALIDA)
// CÁLCULO INTELIGENTE DE HORAS EFECTIVAS Y DESCUENTO DE REFRIGERIO
// ==========================================================
async function procesarRegistroAsistencia(empleadoId, metodo, tipoSolicitado) {
    const lastMarkQuery = `
        SELECT tipo, fecha_hora_marcacion 
        FROM registros_asistencia 
        WHERE empleado_id = $1 
        ORDER BY fecha_hora_marcacion DESC LIMIT 1
    `;
    const lastMarkResult = await db.query(lastMarkQuery, [empleadoId]);

    let tipoAsistencia = tipoSolicitado ? tipoSolicitado.toUpperCase().trim() : null;
    let mensajeExtra = '';

    const ahora = new Date();
    // Ajuste al reloj de Perú (UTC -5)
    const ahoraPeru = new Date(ahora.getTime() - (5 * 60 * 60 * 1000));
    const diaSemana = ahoraPeru.getUTCDay(); // 0: Dom, 1: Lun ... 6: Sáb

    // Validar tipo permitido
    if (tipoAsistencia && tipoAsistencia !== 'INGRESO' && tipoAsistencia !== 'SALIDA') {
        tipoAsistencia = 'INGRESO';
    }

    if (lastMarkResult.rows.length === 0) {
        // Primer registro histórico del empleado: siempre debe ser INGRESO
        if (tipoAsistencia && tipoAsistencia !== 'INGRESO') {
            return {
                ok: false,
                status: 400,
                accionSugerida: 'INGRESO',
                error: 'No registra un INGRESO previo. Por favor, marque primero su ENTRADA / INGRESO.'
            };
        }
        tipoAsistencia = 'INGRESO';
    } else {
        const ultimaMarcacion = lastMarkResult.rows[0];
        const fechaUltima = new Date(ultimaMarcacion.fecha_hora_marcacion);
        const fechaUltimaPeru = new Date(fechaUltima.getTime() - (5 * 60 * 60 * 1000));
        
        const esMismoDia = fechaUltimaPeru.getUTCFullYear() === ahoraPeru.getUTCFullYear() && 
                           fechaUltimaPeru.getUTCMonth() === ahoraPeru.getUTCMonth() && 
                           fechaUltimaPeru.getUTCDate() === ahoraPeru.getUTCDate();

        // 1. REGLA: En un nuevo día, la primera marcación NUNCA puede ser distinta a INGRESO
        if (!esMismoDia && tipoAsistencia && tipoAsistencia !== 'INGRESO') {
            return {
                ok: false,
                status: 400,
                accionSugerida: 'INGRESO',
                error: 'No registra un INGRESO el día de hoy. Por favor, marque primero su ENTRADA / INGRESO.'
            };
        }

        // 2. REGLA: Mismo día, evitar estados repetidos
        if (esMismoDia) {
            if (ultimaMarcacion.tipo === 'INGRESO' && tipoAsistencia === 'INGRESO') {
                return {
                    ok: false,
                    status: 400,
                    accionSugerida: 'SALIDA',
                    error: 'Usted ya registró su INGRESO el día de hoy. Si terminó su jornada, marque SALIDA.'
                };
            }
            if (ultimaMarcacion.tipo === 'SALIDA' && tipoAsistencia === 'SALIDA') {
                return {
                    ok: false,
                    status: 400,
                    accionSugerida: 'INGRESO',
                    error: 'Usted ya completó su jornada marcando SALIDA el día de hoy.'
                };
            }
            if (ultimaMarcacion.tipo === 'SALIDA' && tipoAsistencia === 'INGRESO') {
                return {
                    ok: false,
                    status: 400,
                    accionSugerida: 'INGRESO',
                    error: 'Usted ya completó su jornada laboral el día de hoy.'
                };
            }
        }

        // 3. Auto-asignación inteligente si no se envió tipo
        if (!tipoAsistencia) {
            if (!esMismoDia) {
                tipoAsistencia = 'INGRESO';
            } else if (ultimaMarcacion.tipo === 'INGRESO') {
                tipoAsistencia = 'SALIDA';
            } else {
                tipoAsistencia = 'INGRESO';
            }
        }

        // 4. AUTO-CIERRE de turno anterior por omisión si quedó abierto ayer
        if (!esMismoDia && ultimaMarcacion.tipo === 'INGRESO' && tipoAsistencia === 'INGRESO') {
            const fechaSalidaAutomatica = new Date(fechaUltima);
            fechaSalidaAutomatica.setHours(20, 0, 0, 0); // 8:00 PM del día del turno abierto
            
            const autoSalidaQuery = `
                INSERT INTO registros_asistencia (empleado_id, metodo, tipo, horas_trabajadas, minutos_netos, fecha_hora_marcacion) 
                VALUES ($1, $2, $3, $4, $5, $6)
            `;
            await db.query(autoSalidaQuery, [empleadoId, 'SISTEMA_AUTO', 'SALIDA', 'Turno cerrado auto', null, fechaSalidaAutomatica]);
            mensajeExtra = ' (Aviso: Se cerró automáticamente tu turno de ayer por omisión)';
        }
    }

    // Consultar datos del empleado (horario y refrigerio)
    const empResult = await db.query(`
        SELECT nombre_completo, area, dias_laborables, hora_ingreso, hora_salida, 
               hora_ingreso_sab, hora_salida_sab, inicio_refrigerio, fin_refrigerio 
        FROM empleados WHERE id = $1
    `, [empleadoId]);
    const emp = empResult.rows[0];
    const nombreColaborador = emp?.nombre_completo || 'Colaborador';

    let horasTrabajadasTexto = null;
    let minutosNetos = null;
    let mensajeConfirmacion = '';

    if (tipoAsistencia === 'SALIDA') {
        // Buscar el INGRESO de hoy para calcular tiempo trabajado
        const ingresoQuery = `
            SELECT fecha_hora_marcacion 
            FROM registros_asistencia 
            WHERE empleado_id = $1 
              AND tipo = 'INGRESO' 
              AND (fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date
            ORDER BY fecha_hora_marcacion DESC LIMIT 1
        `;
        const ingresoResult = await db.query(ingresoQuery, [empleadoId]);
        
        if (ingresoResult.rows.length > 0) {
            const fechaIngreso = new Date(ingresoResult.rows[0].fecha_hora_marcacion);
            const difMs = ahora.getTime() - fechaIngreso.getTime();
            const minutosTotales = Math.max(0, Math.round(difMs / (1000 * 60)));

            let minutosDescuentoRefrigerio = 0;
            // Si es sábado (diaSemana === 6), es medio turno: NO se descuenta almuerzo
            if (diaSemana !== 6) {
                // Lunes a Viernes: calcular duración de refrigerio pactada (default 120 min = 2 horas)
                let duracionRefrigerio = 120;
                if (emp?.inicio_refrigerio && emp?.fin_refrigerio) {
                    const [hI, mI] = emp.inicio_refrigerio.split(':').map(Number);
                    const [hF, mF] = emp.fin_refrigerio.split(':').map(Number);
                    const calc = (hF * 60 + mF) - (hI * 60 + mI);
                    if (calc > 0) duracionRefrigerio = calc;
                }

                // Solo descontar si la jornada fue de 5 horas o más (300 minutos)
                if (minutosTotales >= 300) {
                    minutosDescuentoRefrigerio = duracionRefrigerio;
                }
            }

            minutosNetos = Math.max(0, minutosTotales - minutosDescuentoRefrigerio);
            const h = Math.floor(minutosNetos / 60);
            const m = minutosNetos % 60;
            horasTrabajadasTexto = `${h}h ${m}m`;

            const horasRefrig = Number((minutosDescuentoRefrigerio / 60).toFixed(1));
            let txtRefrig = minutosDescuentoRefrigerio > 0 ? ` (descontando ${horasRefrig}h refrigerio)` : '';
            mensajeConfirmacion = `¡Hasta luego, ${nombreColaborador}! Salida registrada. Tiempo efectivo: ${horasTrabajadasTexto}${txtRefrig}.${mensajeExtra}`;
        } else {
            mensajeConfirmacion = `¡Hasta luego, ${nombreColaborador}! Salida registrada con éxito.${mensajeExtra}`;
        }
    } else {
        const horaStr = ahoraPeru.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true });
        mensajeConfirmacion = `¡Bienvenido/a, ${nombreColaborador}! Ingreso registrado a las ${horaStr}.${mensajeExtra}`;
    }

    // 5. Insertar marcación con horas trabajadas calculadas
    const insertQuery = `
        INSERT INTO registros_asistencia (empleado_id, metodo, tipo, horas_trabajadas, minutos_netos) 
        VALUES ($1, $2, $3, $4, $5) 
        RETURNING id, fecha_hora_marcacion
    `;
    await db.query(insertQuery, [empleadoId, metodo.toUpperCase(), tipoAsistencia, horasTrabajadasTexto, minutosNetos]);
    
    // Siguiente acción sugerida
    const proximaAccion = tipoAsistencia === 'INGRESO' ? 'SALIDA' : 'INGRESO';

    return {
        ok: true,
        nombre: nombreColaborador,
        tipo: tipoAsistencia,
        horas_trabajadas: horasTrabajadasTexto,
        minutos_netos: minutosNetos,
        accionSugerida: proximaAccion,
        mensaje: mensajeConfirmacion
    };
}

// ==========================================================
// ENDPOINTS DE ASISTENCIA
// ==========================================================

// Endpoint: Marcación por PIN Validada en Servidor (VULN-02 RESUELTA)
app.post('/api/asistencia/pin', async (req, res) => {
    const { pin, tipo } = req.body;

    if (!pin || pin.length < 4) {
        return res.status(400).json({ error: 'Debe ingresar un PIN válido de al menos 4 dígitos.' });
    }

    try {
        // Consultar empleados activos
        const result = await db.query('SELECT id, nombre_completo, codigo_pin FROM empleados WHERE activo = TRUE');
        const empleados = result.rows;

        let empleadoAutenticado = null;

        for (const emp of empleados) {
            const storedPin = emp.codigo_pin;
            let esValido = false;

            if (storedPin.startsWith('$2a$') || storedPin.startsWith('$2b$')) {
                // Comprobación segura con bcrypt
                esValido = await bcrypt.compare(pin.toString(), storedPin);
            } else {
                // Compatibilidad transicional con registros legacy en texto plano
                if (storedPin === pin.toString()) {
                    esValido = true;
                    // Auto-actualizar inmediatamente a hash bcrypt en segundo plano
                    const salt = await bcrypt.genSalt(10);
                    const nuevoHash = await bcrypt.hash(pin.toString(), salt);
                    await db.query('UPDATE empleados SET codigo_pin = $1 WHERE id = $2', [nuevoHash, emp.id]);
                }
            }

            if (esValido) {
                empleadoAutenticado = emp;
                break;
            }
        }

        if (!empleadoAutenticado) {
            return res.status(401).json({ error: 'PIN incorrecto. No coincide con ningún trabajador activo.' });
        }

        // Registrar asistencia validada
        const registro = await procesarRegistroAsistencia(empleadoAutenticado.id, 'PIN', tipo);
        if (!registro.ok) {
            return res.status(registro.status).json({ 
                error: registro.error, 
                accionSugerida: registro.accionSugerida 
            });
        }

        return res.status(201).json({
            success: true,
            nombre: registro.nombre,
            tipo: registro.tipo,
            mensaje: registro.mensaje
        });

    } catch (err) {
        console.error('Error POST asistencia/pin:', err);
        res.status(500).json({ error: 'Error interno al procesar marcación por PIN' });
    }
});

// Endpoint: Marcación Facial
app.post('/api/asistencia', async (req, res) => {
    const { empleado_id, metodo, tipo } = req.body;

    if (!empleado_id) {
        return res.status(400).json({ error: 'Falta identificación del empleado.' });
    }

    try {
        // Verificar que el empleado exista y esté activo
        const empCheck = await db.query('SELECT id, nombre_completo FROM empleados WHERE id = $1 AND activo = TRUE', [empleado_id]);
        if (empCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Empleado no autorizado o inactivo.' });
        }

        const registro = await procesarRegistroAsistencia(empleado_id, metodo || 'ROSTRO', tipo);
        if (!registro.ok) {
            return res.status(registro.status).json({ 
                error: registro.error, 
                accionSugerida: registro.accionSugerida 
            });
        }

        res.status(201).json({
            success: true,
            nombre: registro.nombre,
            tipo: registro.tipo,
            mensaje: registro.mensaje
        });
    } catch (err) {
        console.error('Error POST asistencia facial:', err);
        res.status(500).json({ error: 'Error interno al registrar la asistencia' });
    }
});

// ==========================================================
// REPORTES (PROTEGIDOS CON JWT)
// ==========================================================

// Métricas de Reportes (PROTEGIDO)
app.get('/api/reportes/metricas', verificarAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                (SELECT COUNT(*) FROM empleados WHERE activo = TRUE)::int AS empleados_activos,
                (SELECT COUNT(*) FROM registros_asistencia WHERE DATE(fecha_hora_marcacion) = CURRENT_DATE)::int AS asistencias_hoy,
                (SELECT COUNT(*) FROM registros_asistencia WHERE DATE(fecha_hora_marcacion) = CURRENT_DATE AND tipo = 'INGRESO')::int AS ingresos_hoy,
                (SELECT COUNT(*) FROM registros_asistencia WHERE DATE(fecha_hora_marcacion) = CURRENT_DATE AND tipo = 'SALIDA')::int AS salidas_hoy
        `;
        const result = await db.query(query);
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error GET reportes/metricas:', err);
        res.status(500).json({ error: 'Error al obtener métricas' });
    }
});

// Ver Reportes (PROTEGIDO)
app.get('/api/reportes', verificarAdmin, async (req, res) => {
    const { empleado_id, periodo, tipo } = req.query;

    try {
        let query = `
            SELECT r.id, e.nombre_completo, r.fecha_hora_marcacion, r.metodo, r.tipo, r.horas_trabajadas, r.minutos_netos
            FROM registros_asistencia r
            JOIN empleados e ON r.empleado_id = e.id
            WHERE 1=1
        `;
        const values = [];

        if (empleado_id && empleado_id !== 'TODOS') {
            values.push(empleado_id);
            query += ` AND r.empleado_id = $${values.length}`;
        }

        if (tipo && tipo !== 'TODOS') {
            values.push(tipo.toUpperCase());
            query += ` AND r.tipo = $${values.length}`;
        }

        if (periodo === 'DIA') {
            query += ` AND DATE(r.fecha_hora_marcacion) = CURRENT_DATE`;
        } else if (periodo === 'SEMANA') {
            query += ` AND r.fecha_hora_marcacion >= date_trunc('week', CURRENT_DATE)`;
        } else if (periodo === 'MES') {
            query += ` AND r.fecha_hora_marcacion >= date_trunc('month', CURRENT_DATE)`;
        }

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
