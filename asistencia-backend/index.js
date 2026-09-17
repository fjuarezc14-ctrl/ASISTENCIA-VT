const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
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
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
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
    let token = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    } else if (req.query.token) {
        token = req.query.token;
    }

    if (!token) {
        return res.status(401).json({ error: 'Acceso no autorizado. Debe iniciar sesión como administrador.' });
    }

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

            mensajeConfirmacion = `¡Hasta luego, ${nombreColaborador}! Salida registrada. Tiempo efectivo de hoy: ${horasTrabajadasTexto}.${mensajeExtra}`;
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
                (SELECT COUNT(*) FROM registros_asistencia WHERE (fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date)::int AS asistencias_hoy,
                (SELECT COUNT(*) FROM registros_asistencia WHERE (fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date AND tipo = 'INGRESO')::int AS ingresos_hoy,
                (SELECT COUNT(*) FROM registros_asistencia WHERE (fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date AND tipo = 'SALIDA')::int AS salidas_hoy
        `;
        const result = await db.query(query);
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error GET reportes/metricas:', err);
        res.status(500).json({ error: 'Error al obtener métricas' });
    }
});

// Endpoint Dashboard Resumen Integral (PROTEGIDO)
app.get('/api/reportes/dashboard', verificarAdmin, async (req, res) => {
    try {
        // 1. Empleados activos
        const empQuery = await db.query(`
            SELECT id, nombre_completo, area, dias_laborables, hora_ingreso, hora_salida, hora_ingreso_sab, hora_salida_sab 
            FROM empleados WHERE activo = TRUE
        `);
        const empleados = empQuery.rows;
        const totalPlantilla = empleados.length;

        // 2. Marcaciones de hoy (reloj Lima UTC -5)
        const hoyQuery = await db.query(`
            SELECT r.id, r.empleado_id, e.nombre_completo, e.area, r.fecha_hora_marcacion, r.metodo, r.tipo, r.horas_trabajadas, r.minutos_netos,
                   e.hora_ingreso, e.hora_ingreso_sab
            FROM registros_asistencia r
            JOIN empleados e ON r.empleado_id = e.id
            WHERE (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date
            ORDER BY r.fecha_hora_marcacion DESC
        `);
        const registrosHoy = hoyQuery.rows;

        // 3. Presentes hoy
        const idsPresentes = new Set();
        const tardanzasList = [];

        const ahora = new Date();
        const ahoraLima = new Date(ahora.getTime() - (5 * 60 * 60 * 1000));
        const diaSemana = ahoraLima.getUTCDay(); // 6: Sábado

        registrosHoy.forEach(reg => {
            if (reg.tipo === 'INGRESO') {
                idsPresentes.add(reg.empleado_id);

                // Calcular tardanza
                const horaPactada = diaSemana === 6 ? (reg.hora_ingreso_sab || '08:00') : (reg.hora_ingreso || '08:00');
                const [hP, mP] = horaPactada.split(':').map(Number);
                const minutosPactados = hP * 60 + mP;

                const fechaMarc = new Date(reg.fecha_hora_marcacion);
                const fechaMarcLima = new Date(fechaMarc.getTime() - (5 * 60 * 60 * 1000));
                const minutosMarc = fechaMarcLima.getUTCHours() * 60 + fechaMarcLima.getUTCMinutes();

                const difMin = minutosMarc - minutosPactados;
                if (difMin > 5) {
                    tardanzasList.push({
                        empleado_id: reg.empleado_id,
                        nombre: reg.nombre_completo,
                        area: reg.area,
                        hora_ingreso: fechaMarcLima.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true }),
                        turno: horaPactada,
                        minutos_retraso: difMin
                    });
                }
            }
        });

        // 4. Inasistencias de hoy (empleados activos sin ingreso)
        const inasistenciasList = empleados.filter(e => !idsPresentes.has(e.id)).map(e => ({
            empleado_id: e.id,
            nombre: e.nombre_completo,
            area: e.area,
            turno: diaSemana === 6 ? (e.hora_ingreso_sab || '08:00') : (e.hora_ingreso || '08:00')
        }));

        // 5. Últimas actividades
        const actividadReciente = registrosHoy.slice(0, 8).map(r => {
            const f = new Date(r.fecha_hora_marcacion);
            const fLima = new Date(f.getTime() - (5 * 60 * 60 * 1000));
            return {
                id: r.id,
                nombre: r.nombre_completo,
                area: r.area,
                tipo: r.tipo,
                metodo: r.metodo,
                horas_trabajadas: r.horas_trabajadas,
                hora: fLima.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true })
            };
        });

        res.json({
            total_plantilla: totalPlantilla,
            presentes_hoy: idsPresentes.size,
            tardanzas_hoy: tardanzasList.length,
            inasistencias_hoy: inasistenciasList.length,
            tardanzas_lista: tardanzasList,
            inasistencias_lista: inasistenciasList,
            actividad_reciente: actividadReciente
        });
    } catch (err) {
        console.error('Error GET reportes/dashboard:', err);
        res.status(500).json({ error: 'Error al calcular métricas de dashboard' });
    }
});

// Ver Reportes Filtrados (PROTEGIDO)
app.get('/api/reportes', verificarAdmin, async (req, res) => {
    const { empleado_id, periodo, tipo, fecha_inicio, fecha_fin } = req.query;

    try {
        let query = `
            SELECT r.id, r.empleado_id, e.nombre_completo, e.area, 
                   e.hora_ingreso, e.hora_ingreso_sab,
                   r.fecha_hora_marcacion, r.metodo, r.tipo, 
                   r.horas_trabajadas, r.minutos_netos
            FROM registros_asistencia r
            JOIN empleados e ON r.empleado_id = e.id
            WHERE 1=1
        `;
        const values = [];

        if (empleado_id && empleado_id !== 'TODOS' && empleado_id !== 'todos') {
            values.push(empleado_id);
            query += ` AND r.empleado_id = $${values.length}`;
        }

        if (tipo && tipo !== 'TODOS' && tipo !== 'todos') {
            values.push(tipo.toUpperCase());
            query += ` AND r.tipo = $${values.length}`;
        }

        if (fecha_inicio) {
            values.push(fecha_inicio);
            query += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date >= $${values.length}::date`;
        }

        if (fecha_fin) {
            values.push(fecha_fin);
            query += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date <= $${values.length}::date`;
        }

        if (!fecha_inicio && !fecha_fin) {
            if (periodo === 'DIA' || periodo === 'dia') {
                query += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date`;
            } else if (periodo === 'SEMANA' || periodo === 'semana') {
                query += ` AND r.fecha_hora_marcacion >= date_trunc('week', CURRENT_TIMESTAMP)`;
            } else if (periodo === 'MES' || periodo === 'mes') {
                query += ` AND r.fecha_hora_marcacion >= date_trunc('month', CURRENT_TIMESTAMP)`;
            }
        }

        query += ` ORDER BY r.fecha_hora_marcacion DESC LIMIT 1000;`;

        const result = await db.query(query, values);
        res.json(result.rows);
    } catch (err) {
        console.error('Error GET reportes:', err);
        res.status(500).json({ error: 'Error al obtener reportes filtrados' });
    }
});

// Endpoint Exportar a Excel (.xlsx) Profesional para Contabilidad (PROTEGIDO)
app.get('/api/reportes/excel', verificarAdmin, async (req, res) => {
    const { empleado_id, periodo, tipo, fecha_inicio, fecha_fin } = req.query;

    try {
        let query = `
            SELECT r.id, r.empleado_id, e.nombre_completo, e.area, 
                   e.hora_ingreso, e.hora_ingreso_sab,
                   r.fecha_hora_marcacion, r.metodo, r.tipo, 
                   r.horas_trabajadas, r.minutos_netos
            FROM registros_asistencia r
            JOIN empleados e ON r.empleado_id = e.id
            WHERE 1=1
        `;
        const values = [];

        if (empleado_id && empleado_id !== 'TODOS' && empleado_id !== 'todos') {
            values.push(empleado_id);
            query += ` AND r.empleado_id = $${values.length}`;
        }

        if (tipo && tipo !== 'TODOS' && tipo !== 'todos') {
            values.push(tipo.toUpperCase());
            query += ` AND r.tipo = $${values.length}`;
        }

        if (fecha_inicio) {
            values.push(fecha_inicio);
            query += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date >= $${values.length}::date`;
        }

        if (fecha_fin) {
            values.push(fecha_fin);
            query += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date <= $${values.length}::date`;
        }

        if (!fecha_inicio && !fecha_fin) {
            if (periodo === 'DIA' || periodo === 'dia') {
                query += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date`;
            } else if (periodo === 'SEMANA' || periodo === 'semana') {
                query += ` AND r.fecha_hora_marcacion >= date_trunc('week', CURRENT_TIMESTAMP)`;
            } else if (periodo === 'MES' || periodo === 'mes') {
                query += ` AND r.fecha_hora_marcacion >= date_trunc('month', CURRENT_TIMESTAMP)`;
            }
        }

        query += ` ORDER BY r.fecha_hora_marcacion DESC LIMIT 5000;`;

        const result = await db.query(query, values);
        const filas = result.rows;

        // Crear libro de Excel profesional
        const workbook = new ExcelJS.Workbook();
        workbook.creator = 'VT Valetec';
        workbook.created = new Date();

        const sheet = workbook.addWorksheet('Control de Asistencias', {
            views: [{ state: 'frozen', ySplit: 5, showGridLines: true }]
        });

        // Configurar anchos de columna
        sheet.columns = [
            { key: 'id', width: 10 },
            { key: 'empleado', width: 32 },
            { key: 'area', width: 26 },
            { key: 'fecha', width: 14 },
            { key: 'hora', width: 14 },
            { key: 'tipo', width: 16 },
            { key: 'tiempo_texto', width: 20 },
            { key: 'horas_decimal', width: 20 },
            { key: 'minutos_tardanza', width: 20 },
            { key: 'puntualidad', width: 22 },
            { key: 'metodo', width: 16 }
        ];

        // Fila 1: Título Institucional
        sheet.mergeCells('A1:K1');
        const r1 = sheet.getCell('A1');
        r1.value = 'VT VALETEC • CONTROL BIOMÉTRICO Y REGISTRO DE ASISTENCIAS';
        r1.font = { name: 'Arial', size: 13, bold: true, color: { argb: 'FFFFFFFF' } };
        r1.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F172A' } }; // Slate 900
        r1.alignment = { vertical: 'middle', horizontal: 'center' };
        sheet.getRow(1).height = 32;

        // Fila 2: Subtítulo
        sheet.mergeCells('A2:K2');
        const r2 = sheet.getCell('A2');
        r2.value = 'REPORTE OFICIAL CONSOLIDADO PARA CONTROL DE HORAS EFECTIVAS Y PLANILLAS';
        r2.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF94A3B8' } }; // Slate 400
        r2.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } }; // Slate 800
        r2.alignment = { vertical: 'middle', horizontal: 'center' };
        sheet.getRow(2).height = 20;

        // Fila 3: Metadata
        const ahora = new Date();
        const ahoraLima = new Date(ahora.getTime() - (5 * 60 * 60 * 1000));
        const emisionStr = ahoraLima.toISOString().replace('T', ' ').slice(0, 19);

        sheet.mergeCells('A3:E3');
        const r3a = sheet.getCell('A3');
        r3a.value = `Fecha de Emisión: ${emisionStr} (Hora de Lima)`;
        r3a.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF475569' } };
        r3a.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } };
        r3a.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };

        sheet.mergeCells('F3:K3');
        const r3b = sheet.getCell('F3');
        r3b.value = `Total Registros: ${filas.length} | Filtro: ${tipo || 'TODOS'} | Periodo: ${periodo || (fecha_inicio ? `${fecha_inicio} a ${fecha_fin}` : 'Personalizado')}`;
        r3b.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF475569' } };
        r3b.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } };
        r3b.alignment = { vertical: 'middle', horizontal: 'right' };
        sheet.getRow(3).height = 18;

        // Fila 4: Separador en blanco
        sheet.getRow(4).height = 10;

        // Fila 5: Cabecera de Tabla
        const headers = [
            'ID REGISTRO', 'COLABORADOR', 'ÁREA / DEPTO', 'FECHA', 'HORA', 
            'TIPO', 'TIEMPO EFECTIVO', 'HORAS (DECIMAL)', 'MIN. TARDANZA', 'PUNTUALIDAD', 'MÉTODO'
        ];
        const row5 = sheet.getRow(5);
        row5.values = headers;
        row5.height = 26;
        row5.eachCell((cell) => {
            cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFFFFFFF' } };
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E3A8A' } }; // Blue 900
            cell.alignment = { vertical: 'middle', horizontal: 'center' };
            cell.border = {
                top: { style: 'medium', color: { argb: 'FF0F172A' } },
                bottom: { style: 'medium', color: { argb: 'FF0F172A' } }
            };
        });

        // Insertar datos
        const borderThin = {
            top: { style: 'thin', color: { argb: 'FFE2E8F0' } },
            bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } },
            left: { style: 'thin', color: { argb: 'FFE2E8F0' } },
            right: { style: 'thin', color: { argb: 'FFE2E8F0' } }
        };

        let startRowIndex = 6;
        filas.forEach((r, idx) => {
            const rowIdx = startRowIndex + idx;
            const f = new Date(r.fecha_hora_marcacion);
            const fLima = new Date(f.getTime() - (5 * 60 * 60 * 1000));
            const fechaStr = fLima.toISOString().split('T')[0];
            const horaStr = fLima.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true });

            const esIngreso = r.tipo === 'INGRESO';
            const horasDecimal = r.minutos_netos ? Number((r.minutos_netos / 60).toFixed(2)) : null;

            // Tardanza
            let minTardanza = 0;
            let puntualidadStr = 'Salida';
            if (esIngreso) {
                const diaSem = fLima.getUTCDay();
                const horaPactada = diaSem === 6 ? (r.hora_ingreso_sab || '08:00') : (r.hora_ingreso || '08:00');
                const [hP, mP] = horaPactada.split(':').map(Number);
                const minPactados = hP * 60 + mP;
                const minMarc = fLima.getUTCHours() * 60 + fLima.getUTCMinutes();
                const difMin = minMarc - minPactados;

                if (difMin > 5) {
                    minTardanza = difMin;
                    puntualidadStr = `Tardanza (+${difMin}m)`;
                } else {
                    puntualidadStr = 'A Tiempo';
                }
            }

            const isZebra = idx % 2 === 1;
            const rowBg = isZebra ? 'FFF8FAFC' : 'FFFFFFFF';

            const row = sheet.getRow(rowIdx);
            row.height = 20;
            row.values = [
                `#${r.id}`,
                r.nombre_completo,
                r.area || 'General',
                fechaStr,
                horaStr,
                esIngreso ? 'ENTRADA' : 'SALIDA',
                r.horas_trabajadas || (esIngreso ? 'En jornada' : '-'),
                horasDecimal,
                minTardanza,
                puntualidadStr,
                r.metodo === 'PIN' ? 'PIN' : (r.metodo === 'SISTEMA_AUTO' ? 'AUTO' : 'ROSTRO')
            ];

            // Formato de celdas
            row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                cell.font = { name: 'Arial', size: 9, color: { argb: 'FF1E293B' } };
                cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: rowBg } };
                cell.border = borderThin;
                cell.alignment = { vertical: 'middle', horizontal: 'center' };

                if (colNumber === 2 || colNumber === 3) { // Colaborador y Área
                    cell.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
                }

                if (colNumber === 6) { // Tipo
                    cell.font = { 
                        name: 'Arial', size: 9, bold: true, 
                        color: { argb: esIngreso ? 'FF059669' : 'FFE11D48' } // Verde / Rosa
                    };
                }

                if (colNumber === 8) { // Horas Decimal
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0.00';
                    if (horasDecimal) {
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF1E3A8A' } };
                    }
                }

                if (colNumber === 9) { // Minutos Tardanza
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0';
                    if (minTardanza > 0) {
                        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFEF3C7' } }; // Amber 100
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFB45309' } }; // Amber 700
                    }
                }

                if (colNumber === 10 && minTardanza > 0) {
                    cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFB45309' } };
                }
            });
        });

        // Fila de Totales
        const lastDataRow = startRowIndex + filas.length - 1;
        const totalRowIdx = lastDataRow + 1;

        if (filas.length > 0) {
            sheet.mergeCells(`A${totalRowIdx}:G${totalRowIdx}`);
            const totalLabelCell = sheet.getCell(`A${totalRowIdx}`);
            totalLabelCell.value = 'TOTAL GENERAL ACUMULADO:';
            totalLabelCell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF0F172A' } };
            totalLabelCell.alignment = { vertical: 'middle', horizontal: 'right', indent: 1 };

            // Total Horas Decimales
            const totalHorasCell = sheet.getCell(`H${totalRowIdx}`);
            totalHorasCell.value = { formula: `SUM(H${startRowIndex}:H${lastDataRow})` };
            totalHorasCell.font = { name: 'Arial', size: 10, bold: true, color: { argb: 'FF1E3A8A' } };
            totalHorasCell.numFmt = '#,##0.00';
            totalHorasCell.alignment = { vertical: 'middle', horizontal: 'right' };

            // Total Minutos Tardanza
            const totalTardanzasCell = sheet.getCell(`I${totalRowIdx}`);
            totalTardanzasCell.value = { formula: `SUM(I${startRowIndex}:I${lastDataRow})` };
            totalTardanzasCell.font = { name: 'Arial', size: 10, bold: true, color: { argb: 'FFB45309' } };
            totalTardanzasCell.numFmt = '#,##0';
            totalTardanzasCell.alignment = { vertical: 'middle', horizontal: 'right' };

            const totalRow = sheet.getRow(totalRowIdx);
            totalRow.height = 24;
            totalRow.eachCell({ includeEmpty: true }, (cell) => {
                cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } };
                cell.border = {
                    top: { style: 'medium', color: { argb: 'FF475569' } },
                    bottom: { style: 'double', color: { argb: 'FF0F172A' } },
                    left: { style: 'thin', color: { argb: 'FFE2E8F0' } },
                    right: { style: 'thin', color: { argb: 'FFE2E8F0' } }
                };
            });
        }

        // Activar AutoFiltros
        sheet.autoFilter = `A5:K5`;

        // Generar archivo binario y enviar
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="Reporte_Asistencias_Valetec_${ahoraLima.toISOString().split('T')[0]}.xlsx"`);

        await workbook.xlsx.write(res);
        res.end();

    } catch (err) {
        console.error('Error GET reportes/excel:', err);
        res.status(500).json({ error: 'Error al generar archivo Excel' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor backend corriendo en: http://localhost:${PORT}`);
});
