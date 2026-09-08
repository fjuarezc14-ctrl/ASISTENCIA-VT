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
            SELECT e.id, e.nombre_completo, e.activo, e.creado_en,
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
    const { nombre_completo, codigo_pin, face_descriptor } = req.body;

    if (!nombre_completo || !codigo_pin || !face_descriptor) {
        return res.status(400).json({ error: 'Faltan datos obligatorios (nombre, pin o rostro).' });
    }

    try {
        // VULN-02 CORREGIDA: Hasheo seguro del PIN con bcrypt antes de guardar
        const salt = await bcrypt.genSalt(10);
        const hashedPin = await bcrypt.hash(codigo_pin.toString(), salt);

        const query = `
            INSERT INTO empleados (nombre_completo, codigo_pin, face_descriptor) 
            VALUES ($1, $2, $3) 
            RETURNING id, nombre_completo
        `;
        
        const result = await db.query(query, [
            nombre_completo.trim(), 
            hashedPin, 
            JSON.stringify(face_descriptor)
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
// LÓGICA CENTRAL DE MARCACIÓN (HORA PERÚ Y VALIDACIÓN DE ESTADO)
// ==========================================================
async function procesarRegistroAsistencia(empleadoId, metodo, tipoSolicitado) {
    const lastMarkQuery = `
        SELECT tipo, fecha_hora_marcacion 
        FROM registros_asistencia 
        WHERE empleado_id = $1 
        ORDER BY fecha_hora_marcacion DESC LIMIT 1
    `;
    const lastMarkResult = await db.query(lastMarkQuery, [empleadoId]);

    let tipoAsistencia = tipoSolicitado ? tipoSolicitado.toUpperCase() : null;
    let mensajeExtra = '';

    const ahora = new Date();
    // Ajuste al reloj de Perú (UTC -5)
    const ahoraPeru = new Date(ahora.getTime() - (5 * 60 * 60 * 1000));

    if (lastMarkResult.rows.length === 0) {
        // Primer registro histórico del empleado: siempre debe ser INGRESO
        if (tipoAsistencia === 'SALIDA') {
            return {
                ok: false,
                status: 400,
                accionSugerida: 'INGRESO',
                error: 'No registra un INGRESO previo. Por favor, marque primero su INGRESO.'
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

        // 1. REGLA: En un nuevo día, la primera marcación NUNCA puede ser SALIDA
        if (!esMismoDia && tipoAsistencia === 'SALIDA') {
            return {
                ok: false,
                status: 400,
                accionSugerida: 'INGRESO',
                error: 'No registra un INGRESO el día de hoy. Por favor, marque primero su INGRESO.'
            };
        }

        // 2. REGLA: Bloqueo por estado repetido en el mismo día
        if (esMismoDia && tipoAsistencia === ultimaMarcacion.tipo) {
            const accionCorrecta = ultimaMarcacion.tipo === 'INGRESO' ? 'SALIDA' : 'INGRESO';
            return {
                ok: false,
                status: 400,
                accionSugerida: accionCorrecta,
                error: `Usted ya marcó ${ultimaMarcacion.tipo} hoy. Por favor, marque ${accionCorrecta}.`
            };
        }

        // 3. Fallback si no especificó tipo
        if (!tipoAsistencia) {
            tipoAsistencia = esMismoDia && ultimaMarcacion.tipo === 'INGRESO' ? 'SALIDA' : 'INGRESO';
        }

        // 4. AUTO-CIERRE de turno anterior por omisión (ej. si olvidó marcar salida ayer o salió a ventas)
        if (!esMismoDia && ultimaMarcacion.tipo === 'INGRESO' && tipoAsistencia === 'INGRESO') {
            const fechaSalidaAutomatica = new Date(fechaUltima);
            fechaSalidaAutomatica.setHours(20, 0, 0, 0); // 8:00 PM del día del turno abierto
            
            const autoSalidaQuery = `
                INSERT INTO registros_asistencia (empleado_id, metodo, tipo, fecha_hora_marcacion) 
                VALUES ($1, $2, $3, $4)
            `;
            await db.query(autoSalidaQuery, [empleadoId, 'SISTEMA_AUTO', 'SALIDA', fechaSalidaAutomatica]);
            mensajeExtra = ' (Aviso: Se cerró automáticamente tu turno anterior por omisión)';
        }
    }

    // 5. Insertar marcación
    const insertQuery = `
        INSERT INTO registros_asistencia (empleado_id, metodo, tipo) 
        VALUES ($1, $2, $3) 
        RETURNING id, fecha_hora_marcacion
    `;
    await db.query(insertQuery, [empleadoId, metodo.toUpperCase(), tipoAsistencia]);
    
    const empResult = await db.query('SELECT nombre_completo FROM empleados WHERE id = $1', [empleadoId]);
    return {
        ok: true,
        nombre: empResult.rows[0]?.nombre_completo || 'Desconocido',
        tipo: tipoAsistencia,
        mensaje: `Asistencia de ${tipoAsistencia} registrada${mensajeExtra}`
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
            SELECT r.id, e.nombre_completo, r.fecha_hora_marcacion, r.metodo, r.tipo
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
