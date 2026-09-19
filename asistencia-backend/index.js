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
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

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

// Endpoint 4: Actualizar / Modificar empleado (PROTEGIDO)
app.put('/api/empleados/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    const { 
        nombre_completo, codigo_pin, face_descriptor, 
        area, dias_laborables, 
        hora_ingreso, hora_salida, 
        hora_ingreso_sab, hora_salida_sab, 
        inicio_refrigerio, fin_refrigerio 
    } = req.body;

    if (!nombre_completo) {
        return res.status(400).json({ error: 'El nombre completo es obligatorio.' });
    }

    try {
        const empCheck = await db.query('SELECT id, codigo_pin, face_descriptor FROM empleados WHERE id = $1', [id]);
        if (empCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Empleado no encontrado.' });
        }

        let hashedPin = empCheck.rows[0].codigo_pin;
        if (codigo_pin && codigo_pin.toString().trim().length === 4) {
            const salt = await bcrypt.genSalt(10);
            hashedPin = await bcrypt.hash(codigo_pin.toString().trim(), salt);
        }

        let faceDescriptorFinal = empCheck.rows[0].face_descriptor;
        if (face_descriptor && Array.isArray(face_descriptor) && face_descriptor.length > 0) {
            faceDescriptorFinal = JSON.stringify(face_descriptor);
        } else if (typeof faceDescriptorFinal === 'object' && faceDescriptorFinal !== null) {
            faceDescriptorFinal = JSON.stringify(faceDescriptorFinal);
        }

        const updateQuery = `
            UPDATE empleados SET
                nombre_completo = $1,
                codigo_pin = $2,
                face_descriptor = $3,
                area = $4,
                dias_laborables = $5,
                hora_ingreso = $6,
                hora_salida = $7,
                hora_ingreso_sab = $8,
                hora_salida_sab = $9,
                inicio_refrigerio = $10,
                fin_refrigerio = $11
            WHERE id = $12
            RETURNING id, nombre_completo, area, dias_laborables, hora_ingreso, hora_salida, activo
        `;

        const result = await db.query(updateQuery, [
            nombre_completo.trim(),
            hashedPin,
            faceDescriptorFinal,
            area || 'Desarrollo de Software',
            dias_laborables || 'Lun, Mar, Mié, Jue, Vie',
            hora_ingreso || '08:00',
            hora_salida || '18:00',
            hora_ingreso_sab || '08:00',
            hora_salida_sab || '13:00',
            inicio_refrigerio || '13:00',
            fin_refrigerio || '15:00',
            id
        ]);

        console.log(`✏️ Empleado actualizado: ${result.rows[0].nombre_completo} (ID: ${id})`);
        res.json({
            success: true,
            mensaje: 'Colaborador actualizado correctamente',
            empleado: result.rows[0]
        });

    } catch (err) {
        console.error('Error PUT /api/empleados/:id:', err);
        res.status(500).json({ error: 'Error al actualizar el colaborador: ' + (err.message || 'Error de base de datos') });
    }
});

// Endpoint 5: Eliminar permanentemente un empleado (PROTEGIDO)
app.delete('/api/empleados/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query('DELETE FROM empleados WHERE id = $1 RETURNING id, nombre_completo', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Empleado no encontrado.' });
        }
        const empEliminado = result.rows[0];
        console.log(`🗑️ Empleado eliminado permanentemente: ${empEliminado.nombre_completo} (ID: ${empEliminado.id})`);
        res.json({
            success: true,
            mensaje: `El colaborador "${empEliminado.nombre_completo}" ha sido eliminado del sistema con éxito.`,
            empleado: empEliminado
        });
    } catch (err) {
        console.error('Error DELETE /api/empleados/:id:', err);
        res.status(500).json({ error: 'Error al eliminar el colaborador' });
    }
});

// ==========================================================
// ==========================================================
// LÓGICA CENTRAL DE MARCACIÓN (2 ESTADOS: INGRESO / SALIDA)
// ==========================================================
// CÁLCULO INTELIGENTE DE HORAS EFECTIVAS Y DESCUENTO DE REFRIGERIO
// ==========================================================
function calcularHorasEfectivas(fechaIngreso, fechaSalida, emp, diaSemana) {
    const difMs = fechaSalida.getTime() - fechaIngreso.getTime();
    const minutosTotales = Math.max(0, Math.round(difMs / (1000 * 60)));

    let minutosDescuentoRefrigerio = 0;
    const esFlexible = emp?.hora_ingreso === 'FLEXIBLE' || (emp?.dias_laborables && emp?.dias_laborables.toLowerCase().includes('flexible'));

    // Si es sábado (diaSemana === 6) o modalidad flexible: NO se descuenta refrigerio
    if (diaSemana !== 6 && !esFlexible) {
        // Lunes a Viernes: calcular duración de refrigerio pactada (default 120 min = 2 horas)
        let duracionRefrigerio = 120;
        if (emp?.inicio_refrigerio && emp?.fin_refrigerio) {
            const [hI, mI] = emp.inicio_refrigerio.split(':').map(Number);
            const [hF, mF] = emp.fin_refrigerio.split(':').map(Number);
            const calc = (hF * 60 + mF) - (hI * 60 + mI);
            duracionRefrigerio = calc >= 0 ? calc : 0;
        }

        // Solo descontar si la jornada fue de 5 horas o más (300 minutos)
        if (minutosTotales >= 300) {
            minutosDescuentoRefrigerio = duracionRefrigerio;
        }
    }

    const minutosNetos = Math.max(0, minutosTotales - minutosDescuentoRefrigerio);
    const h = Math.floor(minutosNetos / 60);
    const m = minutosNetos % 60;
    const horasTrabajadasTexto = `${h}h ${m}m`;

    return { minutosTotales, minutosDescuentoRefrigerio, minutosNetos, horasTrabajadasTexto };
}

function calcularFechaSalidaAuto(fechaIngreso, emp) {
    const fechaIngresoPeru = new Date(fechaIngreso.getTime() - (5 * 60 * 60 * 1000));
    const anioP = fechaIngresoPeru.getUTCFullYear();
    const mesP = String(fechaIngresoPeru.getUTCMonth() + 1).padStart(2, '0');
    const diaP = String(fechaIngresoPeru.getUTCDate()).padStart(2, '0');
    const diaSemana = fechaIngresoPeru.getUTCDay(); // 0: Dom, 6: Sáb

    // Lunes a Viernes: 20:00 (8:00 PM). Sábado: hora_salida_sab (por defecto 13:00)
    let horaSalidaTarget = diaSemana === 6 ? (emp?.hora_salida_sab || '13:00') : '20:00';
    if (!horaSalidaTarget || horaSalidaTarget === 'FLEXIBLE') horaSalidaTarget = '20:00';
    const [hS, mS] = horaSalidaTarget.split(':').map(Number);
    const hSStr = String(isNaN(hS) ? 20 : hS).padStart(2, '0');
    const mSStr = String(isNaN(mS) ? 0 : mS).padStart(2, '0');

    // Construcción exacta en hora local de Perú (-05:00)
    let fechaSalida = new Date(`${anioP}-${mesP}-${diaP}T${hSStr}:${mSStr}:00-05:00`);

    // Si el ingreso fue posterior a esa hora, fijar salida 15 minutos después del ingreso
    if (fechaSalida.getTime() <= fechaIngreso.getTime()) {
        fechaSalida = new Date(fechaIngreso.getTime() + 15 * 60 * 1000);
    }

    return { fechaSalida, diaSemana };
}

async function ejecutarAutoCierreJornadas(forzarTodo = false) {
    const ahora = new Date();
    const ahoraPeru = new Date(ahora.getTime() - (5 * 60 * 60 * 1000));
    const horaActualLima = ahoraPeru.getUTCHours();

    const query = `
        SELECT DISTINCT ON (ra.empleado_id)
            ra.id AS ultima_asistencia_id,
            ra.empleado_id,
            ra.tipo,
            ra.fecha_hora_marcacion,
            e.nombre_completo,
            e.area,
            e.dias_laborables,
            e.hora_ingreso,
            e.hora_salida,
            e.hora_ingreso_sab,
            e.hora_salida_sab,
            e.inicio_refrigerio,
            e.fin_refrigerio
        FROM registros_asistencia ra
        JOIN empleados e ON e.id = ra.empleado_id
        WHERE e.activo = TRUE
        ORDER BY ra.empleado_id, ra.fecha_hora_marcacion DESC
    `;

    const result = await db.query(query);
    const jornadasAbiertas = result.rows.filter(r => r.tipo === 'INGRESO');
    const cerradas = [];

    for (const r of jornadasAbiertas) {
        const fechaIngreso = new Date(r.fecha_hora_marcacion);
        const fechaIngresoPeru = new Date(fechaIngreso.getTime() - (5 * 60 * 60 * 1000));

        const esMismoDia = fechaIngresoPeru.getUTCFullYear() === ahoraPeru.getUTCFullYear() &&
                           fechaIngresoPeru.getUTCMonth() === ahoraPeru.getUTCMonth() &&
                           fechaIngresoPeru.getUTCDate() === ahoraPeru.getUTCDate();

        const diaSemanaIngreso = fechaIngresoPeru.getUTCDay();

        let debeCerrar = false;
        if (!esMismoDia) {
            // Turno de día anterior que quedó abierto
            debeCerrar = true;
        } else if (forzarTodo) {
            // Cierre forzado manual desde el panel
            debeCerrar = true;
        } else if (diaSemanaIngreso === 6 && horaActualLima >= 15) {
            // Sábado después de las 3:00 PM (15:00)
            debeCerrar = true;
        } else if (horaActualLima >= 23) {
            // Lunes a viernes a partir de las 11:00 PM (23:00)
            // Permite salidas flexibles hasta las 11:00 PM, y si no marcaron, registra salida a las 8:00 PM
            debeCerrar = true;
        }

        if (debeCerrar) {
            const { fechaSalida, diaSemana } = calcularFechaSalidaAuto(fechaIngreso, r);
            const calculo = calcularHorasEfectivas(fechaIngreso, fechaSalida, r, diaSemana);
            const horasTexto = `${calculo.horasTrabajadasTexto} (Auto)`;

            const insertQuery = `
                INSERT INTO registros_asistencia (
                    empleado_id, metodo, tipo, horas_trabajadas, minutos_netos, fecha_hora_marcacion
                ) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, empleado_id, fecha_hora_marcacion, horas_trabajadas, minutos_netos
            `;

            const insRes = await db.query(insertQuery, [
                r.empleado_id,
                'SISTEMA_AUTO',
                'SALIDA',
                horasTexto,
                calculo.minutosNetos,
                fechaSalida
            ]);

            cerradas.push({
                empleado_id: r.empleado_id,
                nombre_completo: r.nombre_completo,
                fecha_ingreso: r.fecha_hora_marcacion,
                fecha_salida: fechaSalida,
                horas_trabajadas: horasTexto,
                minutos_netos: calculo.minutosNetos,
                asistencia_id: insRes.rows[0]?.id
            });
        }
    }

    if (cerradas.length > 0) {
        console.log(`⏱️ [AUTO-CIERRE] Se cerraron automáticamente ${cerradas.length} jornada(s) abierta(s).`);
    }

    return cerradas;
}

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
            const empPrevioRes = await db.query(`
                SELECT hora_salida_sab, inicio_refrigerio, fin_refrigerio 
                FROM empleados WHERE id = $1
            `, [empleadoId]);
            const empPrevio = empPrevioRes.rows[0];
            const { fechaSalida, diaSemana: diaSemPrevio } = calcularFechaSalidaAuto(fechaUltima, empPrevio);
            const calcPrevio = calcularHorasEfectivas(fechaUltima, fechaSalida, empPrevio, diaSemPrevio);
            const horasTextoPrevio = `${calcPrevio.horasTrabajadasTexto} (Auto)`;

            const autoSalidaQuery = `
                INSERT INTO registros_asistencia (empleado_id, metodo, tipo, horas_trabajadas, minutos_netos, fecha_hora_marcacion) 
                VALUES ($1, $2, $3, $4, $5, $6)
            `;
            await db.query(autoSalidaQuery, [empleadoId, 'SISTEMA_AUTO', 'SALIDA', horasTextoPrevio, calcPrevio.minutosNetos, fechaSalida]);
            mensajeExtra = ' (Aviso: Se cerró automáticamente tu turno anterior por omisión)';
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
            const calculo = calcularHorasEfectivas(fechaIngreso, ahora, emp, diaSemana);
            minutosNetos = calculo.minutosNetos;
            horasTrabajadasTexto = calculo.horasTrabajadasTexto;

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
    const insertResult = await db.query(insertQuery, [empleadoId, metodo.toUpperCase(), tipoAsistencia, horasTrabajadasTexto, minutosNetos]);
    const nuevoRegistroId = insertResult.rows[0]?.id;

    // Si es un INGRESO, vincular cualquier justificación o tolerancia previa para hoy
    if (tipoAsistencia === 'INGRESO' && nuevoRegistroId) {
        try {
            await db.query(`
                UPDATE justificaciones_asistencia 
                SET asistencia_id = $1 
                WHERE empleado_id = $2 
                  AND fecha = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date 
                  AND asistencia_id IS NULL
            `, [nuevoRegistroId, empleadoId]);
        } catch (e) {
            console.error('Error al vincular justificación previa:', e);
        }
    }
    
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
// MÓDULO DE JUSTIFICACIONES, TOLERANCIAS Y PERMISOS (GERENCIA)
// ==========================================================

// 1. Obtener justificaciones (con filtros opcionales)
app.get('/api/justificaciones', verificarAdmin, async (req, res) => {
    const { fecha, empleado_id, tipo } = req.query;
    try {
        let query = `
            SELECT j.id, j.empleado_id, e.nombre_completo, e.area, j.asistencia_id, 
                   j.fecha, j.tipo, j.hora_tolerancia, j.motivo, j.autorizado_por, j.creado_en
            FROM justificaciones_asistencia j
            JOIN empleados e ON j.empleado_id = e.id
            WHERE 1=1
        `;
        const values = [];

        if (fecha) {
            values.push(fecha);
            query += ` AND j.fecha = $${values.length}`;
        }
        if (empleado_id && empleado_id !== 'TODOS') {
            values.push(empleado_id);
            query += ` AND j.empleado_id = $${values.length}`;
        }
        if (tipo && tipo !== 'TODOS') {
            values.push(tipo);
            query += ` AND j.tipo = $${values.length}`;
        }

        query += ` ORDER BY j.fecha DESC, j.creado_en DESC LIMIT 500;`;
        const result = await db.query(query, values);
        res.json(result.rows);
    } catch (err) {
        console.error('Error GET /api/justificaciones:', err);
        res.status(500).json({ error: 'Error al consultar justificaciones' });
    }
});

// 2. Registrar o conceder justificación / tolerancia
app.post('/api/justificaciones', verificarAdmin, async (req, res) => {
    let { empleado_id, asistencia_id, tipo, fecha, hora_tolerancia, motivo } = req.body;

    try {
        // Si viene con asistencia_id pero sin empleado_id ni fecha, obtenerlos del registro
        if (asistencia_id && (!empleado_id || !fecha)) {
            const regQuery = await db.query(
                `SELECT empleado_id, (fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date AS fecha 
                 FROM registros_asistencia WHERE id = $1`,
                [asistencia_id]
            );
            if (regQuery.rows.length === 0) {
                return res.status(404).json({ error: 'Registro de asistencia no encontrado.' });
            }
            empleado_id = empleado_id || regQuery.rows[0].empleado_id;
            fecha = fecha || regQuery.rows[0].fecha;
        }

        if (!empleado_id) {
            return res.status(400).json({ error: 'Debe indicar el colaborador.' });
        }

        if (!fecha) {
            const hoyLima = new Date(Date.now() - (5 * 60 * 60 * 1000));
            fecha = hoyLima.toISOString().split('T')[0];
        }

        const tipoFinal = tipo || 'TARDANZA_JUSTIFICADA';
        const motivoFinal = (motivo && motivo.trim()) ? motivo.trim() : 'Autorizado por Gerencia';
        const autorizadoPor = (req.admin && req.admin.username) ? req.admin.username : 'Gerencia';

        // Si ya existe una justificación para esta asistencia, actualizarla
        if (asistencia_id) {
            const checkExist = await db.query(
                `SELECT id FROM justificaciones_asistencia WHERE asistencia_id = $1`,
                [asistencia_id]
            );
            if (checkExist.rows.length > 0) {
                const updateRes = await db.query(
                    `UPDATE justificaciones_asistencia 
                     SET motivo = $1, autorizado_por = $2, tipo = $3
                     WHERE id = $4 RETURNING *`,
                    [motivoFinal, autorizadoPor, tipoFinal, checkExist.rows[0].id]
                );
                return res.json({ success: true, mensaje: 'Justificación actualizada', justificacion: updateRes.rows[0] });
            }
        }

        const insertQuery = `
            INSERT INTO justificaciones_asistencia (
                empleado_id, asistencia_id, fecha, tipo, hora_tolerancia, motivo, autorizado_por
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        `;
        const result = await db.query(insertQuery, [
            empleado_id,
            asistencia_id || null,
            fecha,
            tipoFinal,
            hora_tolerancia || null,
            motivoFinal,
            autorizadoPor
        ]);

        res.status(201).json({
            success: true,
            mensaje: 'Justificación registrada correctamente',
            justificacion: result.rows[0]
        });

    } catch (err) {
        console.error('Error POST /api/justificaciones:', err);
        res.status(500).json({ error: 'Error al registrar la justificación' });
    }
});

// 3. Eliminar / Revocar justificación
app.delete('/api/justificaciones/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query('DELETE FROM justificaciones_asistencia WHERE id = $1 RETURNING id', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Justificación no encontrada.' });
        }
        res.json({ success: true, mensaje: 'Justificación revocada correctamente.' });
    } catch (err) {
        console.error('Error DELETE /api/justificaciones/:id:', err);
        res.status(500).json({ error: 'Error al revocar la justificación' });
    }
});

// ==========================================================
// GESTIÓN DE EXPEDIENTES Y DOCUMENTOS DE EMPLEADOS (PROTEGIDO)
// ==========================================================

// 1. Obtener lista de documentos de un empleado (sin el binario pesado)
app.get('/api/empleados/:id/documentos', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const query = `
            SELECT id, empleado_id, tipo_documento, nombre_archivo, mime_type, tamano_bytes, subido_por, subido_en
            FROM documentos_empleado
            WHERE empleado_id = $1
            ORDER BY subido_en DESC
        `;
        const result = await db.query(query, [id]);
        res.json(result.rows);
    } catch (err) {
        console.error('Error GET /api/empleados/:id/documentos:', err);
        res.status(500).json({ error: 'Error al obtener documentos del colaborador' });
    }
});

// 2. Subir o actualizar documento de un empleado
app.post('/api/empleados/:id/documentos', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    const { tipo_documento, nombre_archivo, mime_type, tamano_bytes, archivo_base64 } = req.body;

    if (!tipo_documento || !nombre_archivo || !archivo_base64) {
        return res.status(400).json({ error: 'Faltan campos requeridos (tipo_documento, nombre_archivo, archivo_base64).' });
    }

    try {
        const empCheck = await db.query('SELECT id, nombre_completo FROM empleados WHERE id = $1', [id]);
        if (empCheck.rows.length === 0) {
            return res.status(404).json({ error: 'El colaborador no existe.' });
        }

        const subidoPor = req.admin?.username || 'Gerencia';

        // Si es uno de los tipos estándar (CV, DNI, RECIBO_SERVICIOS, CONTRATO), reemplazar documento previo
        if (['CV', 'DNI', 'RECIBO_SERVICIOS', 'CONTRATO'].includes(tipo_documento)) {
            await db.query('DELETE FROM documentos_empleado WHERE empleado_id = $1 AND tipo_documento = $2', [id, tipo_documento]);
        }

        const insertQuery = `
            INSERT INTO documentos_empleado (
                empleado_id, tipo_documento, nombre_archivo, mime_type, tamano_bytes, archivo_base64, subido_por
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, empleado_id, tipo_documento, nombre_archivo, mime_type, tamano_bytes, subido_por, subido_en
        `;

        const result = await db.query(insertQuery, [
            id,
            tipo_documento,
            nombre_archivo,
            mime_type || 'application/octet-stream',
            tamano_bytes || 0,
            archivo_base64,
            subidoPor
        ]);

        res.status(201).json({
            success: true,
            mensaje: 'Documento subido correctamente.',
            documento: result.rows[0]
        });
    } catch (err) {
        console.error('Error POST /api/empleados/:id/documentos:', err);
        res.status(500).json({ error: 'Error al subir el documento' });
    }
});

// 3. Descargar / Visualizar documento
app.get('/api/documentos/:id/descargar', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query('SELECT * FROM documentos_empleado WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Documento no encontrado' });
        }

        const doc = result.rows[0];
        let rawBase64 = doc.archivo_base64;
        if (rawBase64.includes('base64,')) {
            rawBase64 = rawBase64.split('base64,')[1];
        }

        const fileBuffer = Buffer.from(rawBase64, 'base64');
        const encodedFilename = encodeURIComponent(doc.nombre_archivo);

        res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
        res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodedFilename}`);
        res.setHeader('Content-Length', fileBuffer.length);
        res.end(fileBuffer);
    } catch (err) {
        console.error('Error GET /api/documentos/:id/descargar:', err);
        res.status(500).json({ error: 'Error al descargar documento' });
    }
});

// 4. Eliminar documento
app.delete('/api/documentos/:id', verificarAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.query('DELETE FROM documentos_empleado WHERE id = $1 RETURNING id', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Documento no encontrado.' });
        }
        res.json({ success: true, mensaje: 'Documento eliminado correctamente.' });
    } catch (err) {
        console.error('Error DELETE /api/documentos/:id:', err);
        res.status(500).json({ error: 'Error al eliminar el documento' });
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

        // 1.1 Justificaciones y tolerancias para hoy
        const justifQuery = await db.query(`
            SELECT id, empleado_id, asistencia_id, tipo, hora_tolerancia, motivo, autorizado_por
            FROM justificaciones_asistencia 
            WHERE fecha = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date
               OR asistencia_id IN (
                   SELECT id FROM registros_asistencia 
                   WHERE (fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date = (CURRENT_TIMESTAMP AT TIME ZONE 'America/Lima')::date
               )
        `);
        const justificacionesHoy = justifQuery.rows;

        // 2. Marcaciones de hoy (reloj Lima UTC -5)
        const hoyQuery = await db.query(`
            SELECT r.id, r.empleado_id, e.nombre_completo, e.area, r.fecha_hora_marcacion, r.metodo, r.tipo, r.horas_trabajadas, r.minutos_netos,
                   e.hora_ingreso, e.hora_ingreso_sab, e.dias_laborables
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

                // Calcular tardanza (excepto si tiene horario flexible / practicante)
                const horaPactada = diaSemana === 6 ? (reg.hora_ingreso_sab || '08:00') : (reg.hora_ingreso || '08:00');
                const esFlexible = horaPactada === 'FLEXIBLE' || reg.hora_ingreso === 'FLEXIBLE' || (reg.dias_laborables && reg.dias_laborables.toLowerCase().includes('flexible'));

                if (!esFlexible) {
                    const [hP, mP] = horaPactada.split(':').map(Number);
                    const minutosPactados = (isNaN(hP) ? 8 : hP) * 60 + (isNaN(mP) ? 0 : mP);

                    const fechaMarc = new Date(reg.fecha_hora_marcacion);
                    const partesMarc = new Intl.DateTimeFormat('es-PE', {
                        timeZone: 'America/Lima',
                        hour: 'numeric',
                        minute: 'numeric',
                        hourCycle: 'h23'
                    }).formatToParts(fechaMarc);
                    const hMarc = parseInt(partesMarc.find(p => p.type === 'hour').value, 10);
                    const mMarc = parseInt(partesMarc.find(p => p.type === 'minute').value, 10);
                    const minutosMarc = hMarc * 60 + mMarc;

                    const difMin = minutosMarc - minutosPactados;
                    if (difMin > 5) {
                        const justif = justificacionesHoy.find(j => 
                            (j.asistencia_id && j.asistencia_id === reg.id) || 
                            (j.empleado_id === reg.empleado_id && (j.tipo === 'TARDANZA_JUSTIFICADA' || j.tipo === 'TOLERANCIA_PREVIA'))
                        );

                        tardanzasList.push({
                            asistencia_id: reg.id,
                            empleado_id: reg.empleado_id,
                            nombre: reg.nombre_completo,
                            area: reg.area,
                            fecha_hora_marcacion: reg.fecha_hora_marcacion,
                            hora_ingreso: fechaMarc.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'America/Lima' }),
                            turno: horaPactada,
                            minutos_retraso: difMin,
                            justificado: !!justif,
                            justificacion_id: justif ? justif.id : null,
                            motivo_justificacion: justif ? justif.motivo : null
                        });
                    }
                }
            }
        });

        // 4. Inasistencias de hoy (empleados activos sin ingreso, excluyendo horario flexible)
        const inasistenciasList = empleados.filter(e => {
            if (idsPresentes.has(e.id)) return false;
            const esFlex = e.hora_ingreso === 'FLEXIBLE' || (e.dias_laborables && e.dias_laborables.toLowerCase().includes('flexible'));
            if (esFlex) return false; // Practicantes / horario flexible no computan falta automática
            return true;
        }).map(e => {
            const justifInasist = justificacionesHoy.find(j => j.empleado_id === e.id);
            return {
                empleado_id: e.id,
                nombre: e.nombre_completo,
                area: e.area,
                turno: diaSemana === 6 ? (e.hora_ingreso_sab || '08:00') : (e.hora_ingreso || '08:00'),
                tolerancia: justifInasist && justifInasist.hora_tolerancia ? justifInasist.hora_tolerancia : null,
                en_permiso: justifInasist && (justifInasist.tipo === 'PERMISO_DIA' || justifInasist.tipo === 'VACACIONES'),
                tipo_permiso: justifInasist ? justifInasist.tipo : null,
                motivo_justificacion: justifInasist ? justifInasist.motivo : null
            };
        });

        // 5. Últimas actividades
        const actividadReciente = registrosHoy.slice(0, 8).map(r => {
            const f = new Date(r.fecha_hora_marcacion);
            return {
                id: r.id,
                nombre: r.nombre_completo,
                area: r.area,
                tipo: r.tipo,
                metodo: r.metodo,
                horas_trabajadas: r.horas_trabajadas,
                fecha_hora_marcacion: r.fecha_hora_marcacion,
                hora: f.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'America/Lima' })
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

// ==========================================================
// FUNCIÓN UNIFICADA: GENERADOR Y PROCESADOR DE REPORTES Y AUDITORÍA
// ==========================================================
async function procesarReporteAsistencias({ db, empleado_id, periodo, tipo, fecha_inicio, fecha_fin }) {
    const ahora = new Date();
    const emisionFecha = ahora.toLocaleDateString('sv', { timeZone: 'America/Lima' });
    const emisionHora = ahora.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'America/Lima' });

    let fInicio = fecha_inicio;
    let fFin = fecha_fin;

    if (!fInicio && !fFin) {
        if (periodo === 'DIA' || periodo === 'dia') {
            fInicio = emisionFecha;
            fFin = emisionFecha;
        } else if (periodo === 'SEMANA' || periodo === 'semana') {
            const [y, m, d] = emisionFecha.split('-').map(Number);
            const dObj = new Date(Date.UTC(y, m - 1, d));
            const day = dObj.getUTCDay();
            const diff = (day === 0 ? -6 : 1) - day;
            dObj.setUTCDate(dObj.getUTCDate() + diff);
            fInicio = dObj.toISOString().split('T')[0];
            fFin = emisionFecha;
        } else if (periodo === 'MES' || periodo === 'mes') {
            const [y, m] = emisionFecha.split('-');
            fInicio = `${y}-${m}-01`;
            fFin = emisionFecha;
        }
    }

    // 1. Obtener empleados activos
    let empQuery = `SELECT id, nombre_completo, area, hora_ingreso, hora_ingreso_sab, dias_laborables, activo FROM empleados WHERE activo = true`;
    const empValues = [];
    if (empleado_id && empleado_id !== 'TODOS' && empleado_id !== 'todos') {
        empValues.push(empleado_id);
        empQuery += ` AND id = $1`;
    }
    empQuery += ` ORDER BY nombre_completo ASC`;
    const empRes = await db.query(empQuery, empValues);
    const empleados = empRes.rows;

    // 2. Obtener justificaciones del periodo
    let justifQuery = `
        SELECT id, empleado_id, asistencia_id, fecha, tipo, hora_tolerancia, motivo, autorizado_por 
        FROM justificaciones_asistencia WHERE 1=1
    `;
    const justifValues = [];
    if (fInicio) {
        justifValues.push(fInicio);
        justifQuery += ` AND fecha >= $${justifValues.length}`;
    }
    if (fFin) {
        justifValues.push(fFin);
        justifQuery += ` AND fecha <= $${justifValues.length}`;
    }
    const justifRes = await db.query(justifQuery, justifValues);
    const justificaciones = justifRes.rows;

    // 3. Obtener registros de asistencia
    let regQuery = `
        SELECT r.id, r.empleado_id, e.nombre_completo, e.area, 
               e.hora_ingreso, e.hora_ingreso_sab, e.dias_laborables,
               r.fecha_hora_marcacion, r.metodo, r.tipo, 
               r.horas_trabajadas, r.minutos_netos,
               j.id AS justificacion_id, j.tipo AS tipo_justificacion,
               j.hora_tolerancia, j.motivo AS motivo_justificacion, j.autorizado_por
        FROM registros_asistencia r
        JOIN empleados e ON r.empleado_id = e.id
        LEFT JOIN LATERAL (
            SELECT j.id, j.tipo, j.hora_tolerancia, j.motivo, j.autorizado_por
            FROM justificaciones_asistencia j
            WHERE (j.asistencia_id = r.id) OR 
                  (j.empleado_id = r.empleado_id AND j.fecha = (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date)
            ORDER BY (j.asistencia_id = r.id) DESC, j.id DESC
            LIMIT 1
        ) j ON true
        WHERE 1=1
    `;
    const regValues = [];
    if (empleado_id && empleado_id !== 'TODOS' && empleado_id !== 'todos') {
        regValues.push(empleado_id);
        regQuery += ` AND r.empleado_id = $${regValues.length}`;
    }
    if (fInicio) {
        regValues.push(fInicio);
        regQuery += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date >= $${regValues.length}::date`;
    }
    if (fFin) {
        regValues.push(fFin);
        regQuery += ` AND (r.fecha_hora_marcacion AT TIME ZONE 'America/Lima')::date <= $${regValues.length}::date`;
    }
    regQuery += ` ORDER BY r.fecha_hora_marcacion DESC LIMIT 5000;`;
    const regRes = await db.query(regQuery, regValues);
    const filasRaw = regRes.rows;

    // 4. Enriquecer registros de asistencia
    const setAsistencias = new Set();
    const registrosProcesados = [];

    for (const r of filasRaw) {
        const f = new Date(r.fecha_hora_marcacion);
        const fechaStr = f.toLocaleDateString('sv', { timeZone: 'America/Lima' });
        const horaStr = f.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'America/Lima' });
        const esIngreso = r.tipo === 'INGRESO';
        const horasDecimal = r.minutos_netos ? Number((r.minutos_netos / 60).toFixed(2)) : null;

        if (esIngreso) {
            setAsistencias.add(`${r.empleado_id}_${fechaStr}`);
        }

        let minTardanza = 0;
        let puntualidadStr = esIngreso ? 'A Tiempo' : 'Salida';
        let esJustificado = !!r.justificacion_id;
        let tieneTardanza = false;
        let motivoTexto = r.motivo_justificacion || '';

        if (esIngreso) {
            const partesLima = new Intl.DateTimeFormat('es-PE', {
                timeZone: 'America/Lima',
                hour: 'numeric', minute: 'numeric', hourCycle: 'h23',
                weekday: 'short'
            }).formatToParts(f);
            const weekday = partesLima.find(p => p.type === 'weekday')?.value?.toLowerCase() || '';
            const esSabado = weekday.includes('sáb') || weekday.includes('sab');
            const horaPactada = esSabado ? (r.hora_ingreso_sab || '08:00') : (r.hora_ingreso || '08:00');
            const esFlexible = horaPactada === 'FLEXIBLE' || r.hora_ingreso === 'FLEXIBLE' || (r.dias_laborables && r.dias_laborables.toLowerCase().includes('flexible'));

            if (esFlexible) {
                minTardanza = 0;
                puntualidadStr = 'Flexible';
            } else {
                const [hP, mP] = horaPactada.split(':').map(Number);
                const minPactados = (isNaN(hP) ? 8 : hP) * 60 + (isNaN(mP) ? 0 : mP);
                const hMarc = parseInt(partesLima.find(p => p.type === 'hour').value, 10);
                const mMarc = parseInt(partesLima.find(p => p.type === 'minute').value, 10);
                const minMarc = hMarc * 60 + mMarc;
                const difMin = minMarc - minPactados;

                if (difMin > 5) {
                    tieneTardanza = true;
                    if (esJustificado) {
                        minTardanza = 0; // Exonerado por Gerencia
                        puntualidadStr = 'Tardanza Justificada';
                        if (!motivoTexto) motivoTexto = 'Autorizado por Gerencia (No descuenta)';
                    } else {
                        minTardanza = difMin; // Sujeto a descuento
                        puntualidadStr = `Tardanza (+${difMin}m)`;
                    }
                } else {
                    puntualidadStr = 'A Tiempo';
                }
            }
        }

        registrosProcesados.push({
            id: r.id,
            empleado_id: r.empleado_id,
            nombre_completo: r.nombre_completo,
            area: r.area || 'General',
            hora_ingreso: r.hora_ingreso,
            hora_ingreso_sab: r.hora_ingreso_sab,
            dias_laborables: r.dias_laborables,
            justificacion_id: r.justificacion_id,
            tipo_justificacion: r.tipo_justificacion,
            hora_tolerancia: r.hora_tolerancia,
            autorizado_por: r.autorizado_por,
            fecha_hora_marcacion: r.fecha_hora_marcacion,
            fecha: fechaStr,
            hora: horaStr,
            tipo: r.tipo,
            horas_trabajadas: r.horas_trabajadas || (esIngreso ? 'En jornada' : '-'),
            minutos_netos: r.minutos_netos,
            horas_decimal: horasDecimal,
            min_tardanza: minTardanza,
            puntualidad: puntualidadStr,
            metodo: r.metodo === 'PIN' ? 'PIN' : (r.metodo === 'SISTEMA_AUTO' ? 'AUTO' : 'ROSTRO'),
            tiene_justificacion: esJustificado,
            motivo_justificacion: motivoTexto,
            es_tardanza: tieneTardanza,
            es_falta: false
        });
    }

    // 5. Detectar Faltas / Inasistencias en el periodo
    const faltasProcesadas = [];
    if (fInicio && fFin) {
        const cur = new Date(`${fInicio}T12:00:00Z`);
        const limitStr = fFin > emisionFecha ? emisionFecha : fFin;
        const end = new Date(`${limitStr}T12:00:00Z`);

        while (cur <= end) {
            const dStr = cur.toISOString().split('T')[0];
            const diaSem = cur.getUTCDay(); // 0: Dom, 6: Sáb

            if (diaSem !== 0) { // Excluir domingos
                for (const emp of empleados) {
                    const esFlex = emp.hora_ingreso === 'FLEXIBLE' || (emp.dias_laborables && emp.dias_laborables.toLowerCase().includes('flexible'));
                    if (esFlex) continue;

                    const key = `${emp.id}_${dStr}`;
                    if (!setAsistencias.has(key)) {
                        const justif = justificaciones.find(j => {
                            const jFechaStr = j.fecha instanceof Date ? j.fecha.toISOString().split('T')[0] : String(j.fecha).split('T')[0];
                            return j.empleado_id === emp.id && jFechaStr === dStr;
                        });

                        const esJustif = !!justif;
                        const motivo = justif ? (justif.motivo || 'Permiso / Vacaciones Autorizado por Gerencia') : 'Inasistencia sin justificar (Descuento de día)';
                        const puntualidad = esJustif ? 'Falta Justificada (Permiso)' : 'Inasistencia Injustificada';

                        faltasProcesadas.push({
                            id: 'FALTA',
                            empleado_id: emp.id,
                            nombre_completo: emp.nombre_completo,
                            area: emp.area || 'General',
                            hora_ingreso: emp.hora_ingreso,
                            hora_ingreso_sab: emp.hora_ingreso_sab,
                            dias_laborables: emp.dias_laborables,
                            justificacion_id: justif ? justif.id : null,
                            tipo_justificacion: justif ? justif.tipo : null,
                            hora_tolerancia: justif ? justif.hora_tolerancia : null,
                            autorizado_por: justif ? justif.autorizado_por : null,
                            fecha_hora_marcacion: `${dStr}T13:00:00.000Z`,
                            fecha: dStr,
                            hora: '-',
                            tipo: 'FALTA',
                            horas_trabajadas: '0h 00m',
                            minutos_netos: 0,
                            horas_decimal: 0,
                            min_tardanza: 0,
                            puntualidad: puntualidad,
                            metodo: '-',
                            tiene_justificacion: esJustif,
                            motivo_justificacion: motivo,
                            es_tardanza: false,
                            es_falta: true,
                            es_falta_injustificada: !esJustif
                        });
                    }
                }
            }
            cur.setUTCDate(cur.getUTCDate() + 1);
        }
    }

    // 6. Filtrar según parámetro tipo
    let registrosFiltrados = [];
    const t = (tipo || 'TODOS').toUpperCase();

    if (t === 'INGRESO') {
        registrosFiltrados = registrosProcesados.filter(r => r.tipo === 'INGRESO');
    } else if (t === 'SALIDA') {
        registrosFiltrados = registrosProcesados.filter(r => r.tipo === 'SALIDA');
    } else if (t === 'TARDANZAS_TODAS' || t === 'TARDANZAS') {
        registrosFiltrados = registrosProcesados.filter(r => r.tipo === 'INGRESO' && r.es_tardanza);
    } else if (t === 'TARDANZAS_INJUSTIFICADAS') {
        registrosFiltrados = registrosProcesados.filter(r => r.tipo === 'INGRESO' && r.min_tardanza > 0);
    } else if (t === 'JUSTIFICADAS') {
        registrosFiltrados = [
            ...registrosProcesados.filter(r => r.tiene_justificacion),
            ...faltasProcesadas.filter(f => f.tiene_justificacion)
        ];
    } else if (t === 'PUNTUALES') {
        registrosFiltrados = registrosProcesados.filter(r => r.tipo === 'INGRESO' && !r.es_tardanza);
    } else if (t === 'FALTAS' || t === 'INASISTENCIAS') {
        registrosFiltrados = faltasProcesadas;
    } else {
        // TODOS: Devuelve marcaciones de asistencia habituales
        registrosFiltrados = registrosProcesados;
    }

    // 7. Consolidar métricas y resumen por colaborador
    const resumenColaboradores = new Map();
    for (const emp of empleados) {
        resumenColaboradores.set(emp.id, {
            id: emp.id,
            nombre: emp.nombre_completo,
            area: emp.area || 'General',
            dias_asistidos: new Set(),
            minutos_netos: 0,
            min_tardanza: 0,
            tardanzas_injustificadas: 0,
            justificaciones: 0,
            faltas_injustificadas: 0,
            faltas_justificadas: 0
        });
    }

    let totalHorasDecimal = 0;
    let totalMinutosNetos = 0;
    let totalMinTardanzaDescontable = 0;
    let totalTardanzasDescontables = 0;
    let totalJustificaciones = 0;
    let totalFaltasInjustificadas = 0;
    let totalFaltasJustificadas = 0;

    registrosProcesados.forEach(r => {
        if (r.minutos_netos) totalMinutosNetos += r.minutos_netos;
        if (r.horas_decimal) totalHorasDecimal += r.horas_decimal;
        if (r.min_tardanza > 0) {
            totalMinTardanzaDescontable += r.min_tardanza;
            totalTardanzasDescontables++;
        }
        if (r.tiene_justificacion) totalJustificaciones++;

        const empStats = resumenColaboradores.get(r.empleado_id);
        if (empStats) {
            if (r.tipo === 'INGRESO') empStats.dias_asistidos.add(r.fecha);
            if (r.minutos_netos) empStats.minutos_netos += r.minutos_netos;
            if (r.min_tardanza > 0) {
                empStats.min_tardanza += r.min_tardanza;
                empStats.tardanzas_injustificadas++;
            }
            if (r.tiene_justificacion) empStats.justificaciones++;
        }
    });

    faltasProcesadas.forEach(f => {
        if (f.es_falta_injustificada) totalFaltasInjustificadas++;
        else totalFaltasJustificadas++;

        const empStats = resumenColaboradores.get(f.empleado_id);
        if (empStats) {
            if (f.es_falta_injustificada) empStats.faltas_injustificadas++;
            else {
                empStats.faltas_justificadas++;
                empStats.justificaciones++;
            }
        }
    });

    const listaResumenColab = Array.from(resumenColaboradores.values()).map(e => ({
        id: e.id,
        nombre: e.nombre,
        area: e.area,
        dias_asistidos: e.dias_asistidos.size,
        minutos_netos: e.minutos_netos,
        horas_texto: `${Math.floor(e.minutos_netos / 60)}h ${e.minutos_netos % 60}m`,
        horas_decimal: Number((e.minutos_netos / 60).toFixed(2)),
        min_tardanza: e.min_tardanza,
        tardanza_horas: Number((e.min_tardanza / 60).toFixed(2)),
        tardanzas_injustificadas: e.tardanzas_injustificadas,
        justificaciones: e.justificaciones,
        faltas_injustificadas: e.faltas_injustificadas,
        faltas_justificadas: e.faltas_justificadas,
        estado: e.faltas_injustificadas > 0 ? 'Con Faltas' : (e.min_tardanza > 0 ? 'Con Tardanzas' : 'Puntual')
    }));

    return {
        registrosFiltrados,
        faltasProcesadas,
        resumenColaboradores: listaResumenColab,
        totales: {
            total_registros: registrosFiltrados.length,
            total_horas_decimal: Number(totalHorasDecimal.toFixed(2)),
            total_horas_texto: `${Math.floor(totalMinutosNetos / 60)}h ${totalMinutosNetos % 60}m`,
            total_min_tardanza: totalMinTardanzaDescontable,
            total_tardanza_texto: `${Math.floor(totalMinTardanzaDescontable / 60)}h ${totalMinTardanzaDescontable % 60}m`,
            total_tardanzas_conteo: totalTardanzasDescontables,
            total_faltas_injustificadas: totalFaltasInjustificadas,
            total_faltas_justificadas: totalFaltasJustificadas,
            total_justificaciones: totalJustificaciones
        },
        meta: {
            fInicio,
            fFin,
            periodo,
            tipo: t,
            emisionFecha,
            emisionHora
        }
    };
}

// Ver Reportes Filtrados (PROTEGIDO)
app.get('/api/reportes', verificarAdmin, async (req, res) => {
    try {
        const data = await procesarReporteAsistencias({
            db,
            empleado_id: req.query.empleado_id,
            periodo: req.query.periodo,
            tipo: req.query.tipo,
            fecha_inicio: req.query.fecha_inicio,
            fecha_fin: req.query.fecha_fin
        });

        res.json(data.registrosFiltrados);
    } catch (err) {
        console.error('Error GET /api/reportes:', err);
        res.status(500).json({ error: 'Error al obtener reportes filtrados' });
    }
});

// Endpoint Exportar a Excel (.xlsx) Profesional para Contabilidad (PROTEGIDO)
app.get('/api/reportes/excel', verificarAdmin, async (req, res) => {
    try {
        const { registrosFiltrados, resumenColaboradores, totales, meta } = await procesarReporteAsistencias({
            db,
            empleado_id: req.query.empleado_id,
            periodo: req.query.periodo,
            tipo: req.query.tipo,
            fecha_inicio: req.query.fecha_inicio,
            fecha_fin: req.query.fecha_fin
        });

        // Crear libro de Excel profesional
        const workbook = new ExcelJS.Workbook();
        workbook.creator = 'VT Valetec';
        workbook.created = new Date();

        // ==========================================
        // HOJA 1: CONTROL DETALLADO DE ASISTENCIAS
        // ==========================================
        const sheet = workbook.addWorksheet('Control de Asistencias', {
            views: [{ state: 'frozen', ySplit: 5, showGridLines: true }]
        });

        sheet.columns = [
            { key: 'id', width: 12 },
            { key: 'empleado', width: 32 },
            { key: 'area', width: 24 },
            { key: 'fecha', width: 14 },
            { key: 'hora', width: 14 },
            { key: 'tipo', width: 16 },
            { key: 'tiempo_texto', width: 20 },
            { key: 'horas_decimal', width: 18 },
            { key: 'minutos_tardanza', width: 20 },
            { key: 'puntualidad', width: 26 },
            { key: 'observacion', width: 36 },
            { key: 'metodo', width: 14 }
        ];

        // Fila 1: Título Institucional
        sheet.mergeCells('A1:L1');
        const r1 = sheet.getCell('A1');
        r1.value = 'VT VALETEC • CONTROL BIOMÉTRICO Y AUDITORÍA DE ASISTENCIAS';
        r1.font = { name: 'Arial', size: 13, bold: true, color: { argb: 'FFFFFFFF' } };
        r1.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F172A' } };
        r1.alignment = { vertical: 'middle', horizontal: 'center' };
        sheet.getRow(1).height = 32;

        // Fila 2: Subtítulo
        sheet.mergeCells('A2:L2');
        const r2 = sheet.getCell('A2');
        r2.value = 'REPORTE OFICIAL CONSOLIDADO PARA CONTROL DE HORAS EFECTIVAS, TARDANZAS Y PLANILLAS';
        r2.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF94A3B8' } };
        r2.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } };
        r2.alignment = { vertical: 'middle', horizontal: 'center' };
        sheet.getRow(2).height = 20;

        // Fila 3: Metadata
        sheet.mergeCells('A3:E3');
        const r3a = sheet.getCell('A3');
        r3a.value = `Emisión: ${meta.emisionFecha} ${meta.emisionHora} (Hora de Lima)`;
        r3a.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF475569' } };
        r3a.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } };
        r3a.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };

        sheet.mergeCells('F3:L3');
        const r3b = sheet.getCell('F3');
        r3b.value = `Total Registros: ${registrosFiltrados.length} | Filtro: ${meta.tipo} | Periodo: ${meta.fInicio || 'Historial'} a ${meta.fFin || 'Hoy'}`;
        r3b.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF475569' } };
        r3b.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } };
        r3b.alignment = { vertical: 'middle', horizontal: 'right' };
        sheet.getRow(3).height = 18;

        // Fila 4: Espacio
        sheet.getRow(4).height = 8;

        // Fila 5: Cabeceras
        const headers = [
            'ID REGISTRO', 'COLABORADOR', 'ÁREA / DEPTO', 'FECHA', 'HORA', 
            'TIPO', 'TIEMPO EFECTIVO', 'HORAS (DECIMAL)', 'MIN. TARDANZA (CON DESCUENTO)', 'ESTADO PUNTUALIDAD', 'JUSTIFICACIÓN / MOTIVO (NO DESCUENTA)', 'MÉTODO'
        ];
        const row5 = sheet.getRow(5);
        row5.values = headers;
        row5.height = 26;
        row5.eachCell((cell) => {
            cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFFFFFFF' } };
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E3A8A' } };
            cell.alignment = { vertical: 'middle', horizontal: 'center' };
            cell.border = {
                top: { style: 'medium', color: { argb: 'FF0F172A' } },
                bottom: { style: 'medium', color: { argb: 'FF0F172A' } }
            };
        });

        const borderThin = {
            top: { style: 'thin', color: { argb: 'FFE2E8F0' } },
            bottom: { style: 'thin', color: { argb: 'FFE2E8F0' } },
            left: { style: 'thin', color: { argb: 'FFE2E8F0' } },
            right: { style: 'thin', color: { argb: 'FFE2E8F0' } }
        };

        const startRowIndex = 6;
        registrosFiltrados.forEach((r, idx) => {
            const rowIdx = startRowIndex + idx;
            const esIngreso = r.tipo === 'INGRESO';
            const esFalta = r.tipo === 'FALTA';
            const isZebra = idx % 2 === 1;
            const rowBg = esFalta ? 'FFFFF1F2' : (isZebra ? 'FFF8FAFC' : 'FFFFFFFF');

            const row = sheet.getRow(rowIdx);
            row.height = 20;
            row.values = [
                esFalta ? 'FALTA' : `#${r.id}`,
                r.nombre_completo,
                r.area,
                r.fecha,
                r.hora,
                esFalta ? 'INASISTENCIA' : (esIngreso ? 'ENTRADA' : 'SALIDA'),
                r.horas_trabajadas,
                r.horas_decimal || 0,
                r.min_tardanza || 0,
                r.puntualidad,
                r.motivo_justificacion || (r.tiene_justificacion ? 'Autorizado por Gerencia' : ''),
                r.metodo
            ];

            row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                cell.font = { name: 'Arial', size: 9, color: { argb: 'FF1E293B' } };
                cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: rowBg } };
                cell.border = borderThin;
                cell.alignment = { vertical: 'middle', horizontal: 'center' };

                if (colNumber === 2 || colNumber === 3) {
                    cell.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
                }

                if (colNumber === 6) { // Tipo
                    cell.font = { 
                        name: 'Arial', size: 9, bold: true, 
                        color: { argb: esFalta ? 'FFE11D48' : (esIngreso ? 'FF059669' : 'FF6366F1') } 
                    };
                }

                if (colNumber === 8) { // Horas decimal
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0.00';
                    if (r.horas_decimal) {
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF1E3A8A' } };
                    }
                }

                if (colNumber === 9) { // Min tardanza
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0';
                    if (r.min_tardanza > 0) {
                        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFEF3C7' } };
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFB45309' } };
                    }
                }

                if (colNumber === 10) { // Puntualidad
                    if (r.puntualidad.includes('Justificada') || r.puntualidad.includes('Permiso')) {
                        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE0F2FE' } };
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF0284C7' } };
                    } else if (r.min_tardanza > 0 || esFalta) {
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFE11D48' } };
                    }
                }

                if (colNumber === 11 && r.tiene_justificacion) {
                    cell.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF0369A1' } };
                }
            });
        });

        // Totales de Hoja 1
        const lastDataRow = startRowIndex + registrosFiltrados.length - 1;
        const totalRowIdx = lastDataRow + 1;

        if (registrosFiltrados.length > 0) {
            sheet.mergeCells(`A${totalRowIdx}:G${totalRowIdx}`);
            const totalLabelCell = sheet.getCell(`A${totalRowIdx}`);
            totalLabelCell.value = 'TOTAL GENERAL ACUMULADO:';
            totalLabelCell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF0F172A' } };
            totalLabelCell.alignment = { vertical: 'middle', horizontal: 'right', indent: 1 };

            const totalHorasCell = sheet.getCell(`H${totalRowIdx}`);
            totalHorasCell.value = { formula: `SUM(H${startRowIndex}:H${lastDataRow})` };
            totalHorasCell.font = { name: 'Arial', size: 10, bold: true, color: { argb: 'FF1E3A8A' } };
            totalHorasCell.numFmt = '#,##0.00';
            totalHorasCell.alignment = { vertical: 'middle', horizontal: 'right' };

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

            // Fila de nota aclaratoria
            const notaRowIdx = totalRowIdx + 1;
            sheet.mergeCells(`A${notaRowIdx}:L${notaRowIdx}`);
            const notaCell = sheet.getCell(`A${notaRowIdx}`);
            notaCell.value = '* NOTA PARA PLANILLA: La columna "MIN. TARDANZA (CON DESCUENTO)" contiene exclusivamente los minutos sujetos a descuento. Toda tardanza o inasistencia autorizada por gerencia figura como 0 min para evitar descuentos indebidos.';
            notaCell.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF64748B' } };
            notaCell.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
            sheet.getRow(notaRowIdx).height = 18;
        }

        sheet.autoFilter = `A5:L5`;

        // ==========================================
        // HOJA 2: RESUMEN CONSOLIDADO POR COLABORADOR
        // ==========================================
        const sheet2 = workbook.addWorksheet('Resumen por Colaborador', {
            views: [{ state: 'frozen', ySplit: 4, showGridLines: true }]
        });

        sheet2.columns = [
            { key: 'colab', width: 32 },
            { key: 'area', width: 24 },
            { key: 'dias', width: 16 },
            { key: 'horas_txt', width: 22 },
            { key: 'horas_dec', width: 18 },
            { key: 'min_tardanza', width: 24 },
            { key: 'horas_tardanza', width: 20 },
            { key: 'faltas', width: 22 },
            { key: 'permisos', width: 24 },
            { key: 'estado', width: 20 }
        ];

        // Título Hoja 2
        sheet2.mergeCells('A1:J1');
        const s2r1 = sheet2.getCell('A1');
        s2r1.value = 'VT VALETEC • RESUMEN CONSOLIDADO DE ASISTENCIAS Y DESCUENTOS POR COLABORADOR';
        s2r1.font = { name: 'Arial', size: 12, bold: true, color: { argb: 'FFFFFFFF' } };
        s2r1.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0F172A' } };
        s2r1.alignment = { vertical: 'middle', horizontal: 'center' };
        sheet2.getRow(1).height = 30;

        sheet2.mergeCells('A2:J2');
        const s2r2 = sheet2.getCell('A2');
        s2r2.value = `Periodo Consultado: ${meta.fInicio || 'Historial'} al ${meta.fFin || 'Hoy'} | Emisión: ${meta.emisionFecha} ${meta.emisionHora}`;
        s2r2.font = { name: 'Arial', size: 8, italic: true, color: { argb: 'FF94A3B8' } };
        s2r2.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } };
        s2r2.alignment = { vertical: 'middle', horizontal: 'center' };
        sheet2.getRow(2).height = 18;

        sheet2.getRow(3).height = 8;

        const headers2 = [
            'COLABORADOR', 'ÁREA / DEPTO', 'DÍAS ASISTIDOS', 'HORAS EFECTIVAS', 'HORAS (DECIMAL)',
            'TARDANZA DESCONTABLE (MIN)', 'EQUIVALENTE EN HORAS', 'FALTAS INJUSTIFICADAS', 'PERMISOS AUTORIZADOS', 'ESTADO AUDITORÍA'
        ];
        const s2Row4 = sheet2.getRow(4);
        s2Row4.values = headers2;
        s2Row4.height = 26;
        s2Row4.eachCell(cell => {
            cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFFFFFFF' } };
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF047857' } }; // Emerald 700
            cell.alignment = { vertical: 'middle', horizontal: 'center' };
            cell.border = {
                top: { style: 'medium', color: { argb: 'FF064E3B' } },
                bottom: { style: 'medium', color: { argb: 'FF064E3B' } }
            };
        });

        resumenColaboradores.forEach((emp, i) => {
            const rowIdx = 5 + i;
            const row = sheet2.getRow(rowIdx);
            row.height = 20;
            const isZebra = i % 2 === 1;

            row.values = [
                emp.nombre,
                emp.area,
                emp.dias_asistidos,
                emp.horas_texto,
                emp.horas_decimal,
                emp.min_tardanza,
                emp.tardanza_horas,
                emp.faltas_injustificadas,
                emp.justificaciones,
                emp.estado
            ];

            row.eachCell({ includeEmpty: true }, (cell, colNumber) => {
                cell.font = { name: 'Arial', size: 9, color: { argb: 'FF1E293B' } };
                cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: isZebra ? 'FFF8FAFC' : 'FFFFFFFF' } };
                cell.border = borderThin;
                cell.alignment = { vertical: 'middle', horizontal: 'center' };

                if (colNumber === 1 || colNumber === 2) {
                    cell.alignment = { vertical: 'middle', horizontal: 'left', indent: 1 };
                }

                if (colNumber === 5) {
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0.00';
                }

                if (colNumber === 6) {
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0';
                    if (emp.min_tardanza > 0) {
                        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFEF3C7' } };
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFB45309' } };
                    }
                }

                if (colNumber === 7) {
                    cell.alignment = { vertical: 'middle', horizontal: 'right' };
                    cell.numFmt = '0.00';
                }

                if (colNumber === 8 && emp.faltas_injustificadas > 0) {
                    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFE4E6' } };
                    cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFE11D48' } };
                }

                if (colNumber === 9 && emp.justificaciones > 0) {
                    cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF0284C7' } };
                }

                if (colNumber === 10) {
                    if (emp.estado === 'Con Faltas') {
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFE11D48' } };
                    } else if (emp.estado === 'Con Tardanzas') {
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FFD97706' } };
                    } else {
                        cell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF059669' } };
                    }
                }
            });
        });

        // Totales Hoja 2
        const lastRow2 = 4 + resumenColaboradores.length;
        const totalRow2Idx = lastRow2 + 1;
        if (resumenColaboradores.length > 0) {
            sheet2.mergeCells(`A${totalRow2Idx}:B${totalRow2Idx}`);
            const tCell = sheet2.getCell(`A${totalRow2Idx}`);
            tCell.value = 'TOTALES GENERALES:';
            tCell.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF0F172A' } };
            tCell.alignment = { vertical: 'middle', horizontal: 'right', indent: 1 };

            sheet2.getCell(`C${totalRow2Idx}`).value = { formula: `SUM(C5:C${lastRow2})` };
            sheet2.getCell(`E${totalRow2Idx}`).value = { formula: `SUM(E5:E${lastRow2})` };
            sheet2.getCell(`F${totalRow2Idx}`).value = { formula: `SUM(F5:F${lastRow2})` };
            sheet2.getCell(`G${totalRow2Idx}`).value = { formula: `SUM(G5:G${lastRow2})` };
            sheet2.getCell(`H${totalRow2Idx}`).value = { formula: `SUM(H5:H${lastRow2})` };
            sheet2.getCell(`I${totalRow2Idx}`).value = { formula: `SUM(I5:I${lastRow2})` };

            const rTot = sheet2.getRow(totalRow2Idx);
            rTot.height = 24;
            rTot.eachCell({ includeEmpty: true }, (c, col) => {
                c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } };
                c.border = {
                    top: { style: 'medium', color: { argb: 'FF475569' } },
                    bottom: { style: 'double', color: { argb: 'FF0F172A' } }
                };
                if ([3, 5, 6, 7, 8, 9].includes(col)) {
                    c.font = { name: 'Arial', size: 9, bold: true, color: { argb: 'FF0F172A' } };
                    c.alignment = { vertical: 'middle', horizontal: 'right' };
                }
            });
        }

        sheet2.autoFilter = `A4:J4`;

        // Nombre de archivo seguro sin variables indefinidas
        const nombreArchivo = `Reporte_Asistencias_Valetec_${meta.emisionFecha}.xlsx`;
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${nombreArchivo}"`);

        await workbook.xlsx.write(res);
        res.end();

    } catch (err) {
        console.error('Error GET /api/reportes/excel:', err);
        res.status(500).json({ error: 'Error al generar archivo Excel' });
    }
});

// ==========================================================
// AUTO-CIERRE DE JORNADAS Y CONTROL DE JORNADAS ABIERTAS (PROTEGIDO)
// ==========================================================

// 1. Consultar colaboradores que actualmente tienen jornada abierta (sin salida registrada)
app.get('/api/asistencia/jornadas-abiertas', verificarAdmin, async (req, res) => {
    try {
        const query = `
            SELECT DISTINCT ON (ra.empleado_id)
                ra.id AS asistencia_id,
                ra.empleado_id,
                ra.tipo,
                ra.metodo,
                ra.fecha_hora_marcacion AS fecha_ingreso,
                e.nombre_completo,
                e.area,
                e.hora_ingreso,
                e.hora_salida,
                e.hora_ingreso_sab,
                e.hora_salida_sab
            FROM registros_asistencia ra
            JOIN empleados e ON e.id = ra.empleado_id
            WHERE e.activo = TRUE
            ORDER BY ra.empleado_id, ra.fecha_hora_marcacion DESC
        `;
        const result = await db.query(query);
        const abiertas = result.rows.filter(r => r.tipo === 'INGRESO');

        const ahora = new Date();
        const detalle = abiertas.map(r => {
            const fIngreso = new Date(r.fecha_ingreso);
            const minutosTranscurridos = Math.max(0, Math.round((ahora.getTime() - fIngreso.getTime()) / (1000 * 60)));
            const h = Math.floor(minutosTranscurridos / 60);
            const m = minutosTranscurridos % 60;
            return {
                ...r,
                tiempo_transcurrido: `${h}h ${m}m`,
                minutos_transcurridos: minutosTranscurridos
            };
        });

        res.json({
            total_abiertas: detalle.length,
            jornadas: detalle
        });
    } catch (err) {
        console.error('Error GET /api/asistencia/jornadas-abiertas:', err);
        res.status(500).json({ error: 'Error al consultar jornadas abiertas' });
    }
});

// 2. Disparar manualmente el auto-cierre de jornadas
app.post('/api/asistencia/auto-cierre', verificarAdmin, async (req, res) => {
    const { forzarTodo } = req.body || {};
    try {
        const cerradas = await ejecutarAutoCierreJornadas(!!forzarTodo);
        res.json({
            success: true,
            mensaje: cerradas.length > 0 
                ? `Se cerraron automáticamente ${cerradas.length} jornada(s).` 
                : 'No hay jornadas abiertas que requieran cierre automático en este momento.',
            cerradas_count: cerradas.length,
            cerradas
        });
    } catch (err) {
        console.error('Error POST /api/asistencia/auto-cierre:', err);
        res.status(500).json({ error: 'Error al ejecutar el auto-cierre de jornadas' });
    }
});

// ==========================================================
// VIGILANTE PERIÓDICO DE AUTO-CIERRE EN SEGUNDO PLANO
// ==========================================================
// Ejecuta revisión cada 15 minutos de forma autónoma
setInterval(async () => {
    try {
        await ejecutarAutoCierreJornadas(false);
    } catch (err) {
        console.error('Error en vigilante periódico de auto-cierre:', err);
    }
}, 15 * 60 * 1000);

// Ejecutar una verificación inicial 5 segundos después del inicio del servidor
setTimeout(async () => {
    try {
        console.log('🔍 [INICIO] Verificando jornadas abiertas para auto-cierre...');
        await ejecutarAutoCierreJornadas(false);
    } catch (err) {
        console.error('Error en verificación inicial de auto-cierre:', err);
    }
}, 5000);

app.listen(PORT, () => {
    console.log(`🚀 Servidor backend corriendo en: http://localhost:${PORT}`);
});
