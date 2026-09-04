const crypto = require('node:crypto');
const express = require('express');

// Node 20.12+ puede cargar .env sin instalar dotenv.
process.loadEnvFile();

const app = express();
const port = Number(process.env.PORT || 3000);
const apiVersion = process.env.WHATSAPP_API_VERSION || 'v25.0';
const graphApiBaseUrl = process.env.WHATSAPP_GRAPH_API_URL || 'https://graph.facebook.com';
const accessToken = process.env.WHATSAPP_ACCESS_TOKEN;
const defaultPhoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
const webhookVerifyToken = process.env.WEBHOOK_VERIFY_TOKEN;
const appSecret = process.env.WHATSAPP_APP_SECRET;
const internalApiKey = process.env.INTERNAL_API_KEY;

// Guardamos el body sin parsear para poder validar x-hub-signature-256.
app.use(express.json({
    verify: (request, response, body) => {
        request.rawBody = Buffer.from(body);
    },
}));

function missingConfig(...names) {
    return names.filter((name) => !process.env[name]);
}

function requireWhatsAppConfig(phoneNumberId = defaultPhoneNumberId) {
    const missing = missingConfig('WHATSAPP_ACCESS_TOKEN');
    if (!phoneNumberId) missing.push('WHATSAPP_PHONE_NUMBER_ID');

    if (missing.length > 0) throw new Error(`Faltan variables de entorno: ${missing.join(', ')}`);
}

function hasValidSignature(request) {
    // En desarrollo se puede omitir. En producción conviene configurar el app secret.
    if (!appSecret) return true;

    const signature = request.get('x-hub-signature-256');
    if (!signature || !signature.startsWith('sha256=') || !request.rawBody) return false;

    const expected = Buffer.from(
        `sha256=${crypto.createHmac('sha256', appSecret).update(request.rawBody).digest('hex')}`,
    );
    const received = Buffer.from(signature);

    return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

async function sendWhatsAppText({ to, text, phoneNumberId = defaultPhoneNumberId, replyToMessageId }) {
    requireWhatsAppConfig(phoneNumberId);

    const payload = {
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to,
        type: 'text',
        text: {
            preview_url: false,
            body: text,
        },
    };

    if (replyToMessageId) {
        payload.context = { message_id: replyToMessageId };
    }

    const response = await fetch(
        `${graphApiBaseUrl}/${apiVersion}/${phoneNumberId}/messages`,
        {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(10000),
        },
    );

    const responseText = await response.text();
    let responseBody;
    try {
        responseBody = JSON.parse(responseText);
    } catch {
        responseBody = responseText;
    }

    if (!response.ok) {
        throw new Error(`WhatsApp API ${response.status}: ${JSON.stringify(responseBody)}`);
    }

    return responseBody;
}

function replyFor(text) {
    const normalized = text.trim().toLowerCase();

    if (['hola', 'buenas', 'buenos dias', 'buenas tardes'].includes(normalized)) {
        return '¡Hola! ¿En qué puedo ayudarte?';
    }

    if(["breda"].includes(normalized)) {
        return "Vez q anda bvrenda";
    }

    if (normalized === 'menu' || normalized === 'menú') {
        return 'Opciones disponibles:\n1. Consultar información\n2. Hablar con una persona';
    }

    return `Recibí tu mensaje: "${text}"`;
}

async function processIncomingWebhook(payload) {
    if (payload?.object !== 'whatsapp_business_account') return;

    for (const entry of payload.entry || []) {
        for (const change of entry.changes || []) {
            const value = change.value;
            const phoneNumberId = value?.metadata?.phone_number_id || defaultPhoneNumberId;

            for (const message of value?.messages || []) {
                if (!message.from) continue;

                if (message.type !== 'text' || !message.text?.body) {
                    await sendWhatsAppText({
                        to: message.from,
                        text: 'Por ahora puedo responder mensajes de texto.',
                        phoneNumberId,
                        replyToMessageId: message.id,
                    });
                    continue;
                }

                const text = message.text.body;
                console.log(`Mensaje recibido de ${message.from}: ${text}`);

                await sendWhatsAppText({
                    to: message.from,
                    text: replyFor(text),
                    phoneNumberId,
                    replyToMessageId: message.id,
                });
            }
        }
    }
}

function requireInternalApiKey(request, response, next) {
    if (!internalApiKey) return next();

    const authorization = request.get('authorization');
    if (authorization !== `Bearer ${internalApiKey}`)  return response.status(401).json({ error: 'No autorizado' });

    return next();
}

app.get('/', (request, response) => {
    response.send('WhatsApp API integration is running');
});

app.get('/health', (request, response) => {
    response.json({ ok: true });
});

// Meta llama a este endpoint una vez al configurar el webhook.
app.get('/webhook', (request, response) => {
    const mode = request.query['hub.mode'];
    const token = request.query['hub.verify_token'];
    const challenge = request.query['hub.challenge'];

    if (mode === 'subscribe' && token && token === webhookVerifyToken){
        console.log("Webhook verificado correctamente");
        return response.status(200).send(challenge);
    }

    return response.sendStatus(403);
});

// Meta envía aquí los mensajes entrantes y los estados de entrega.
app.post('/webhook', (request, response) => {
    if (!hasValidSignature(request)) return response.sendStatus(401);

    /* console.log(
        'Webhook recibido desde WhatsApp:',
        JSON.stringify(request.body, null, 2),
    ); */

    // Confirmamos rápido para que Meta no reintente mientras procesamos la respuesta.
    response.sendStatus(200);

    void processIncomingWebhook(request.body).catch((error) => {
        console.error('Error procesando webhook de WhatsApp:', error);
    });
});

// Endpoint propio para enviar un mensaje desde otra parte de tu backend.
app.post('/api/messages', requireInternalApiKey, async (request, response) => {
    const { to, text, phoneNumberId, replyToMessageId } = request.body || {};

    if (!to || !text) {
        return response.status(400).json({
            error: 'Los campos "to" y "text" son obligatorios',
        });
    }

    try {
        const result = await sendWhatsAppText({
            to,
            text,
            phoneNumberId,
            replyToMessageId,
        });

        return response.status(200).json(result);
    } catch (error) {
        console.error('Error enviando mensaje:', error);
        return response.status(502).json({ error: error.message });
    }
});

if (require.main === module) {
    app.listen(port, () => {
        console.log(`Servidor escuchando en http://localhost:${port}`);
        if (!webhookVerifyToken) {
            console.warn('WEBHOOK_VERIFY_TOKEN no está configurado; la verificación de Meta fallará.');
        }
        if (!appSecret) {
            console.warn('WHATSAPP_APP_SECRET no está configurado; se omitirá la validación de firma.');
        }
    });
}

module.exports = { app, replyFor, sendWhatsAppText };
