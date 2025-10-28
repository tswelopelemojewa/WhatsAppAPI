
// index.js
// Dependencies
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios'); // <-- NEW: Required for sending messages

const app = express();

// --- Configuration (Ensure these environment variables are set in Render) ---
const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
const APP_SECRET = process.env.META_APP_SECRET;
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;      // Your Permanent Access Token
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID;    // Your WhatsApp Phone Number ID
// ----------------------------------------------------------------------------


// 1. Middleware to capture raw body buffer (for signature verification)
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

// --- Helper Functions ---

/**
 * Sends a text message back to a user via the WhatsApp Cloud API.
 * @param {string} to - The recipient's WhatsApp ID (wa_id).
 * @param {string} messageText - The text content of the message.
 */
async function sendTextMessage(to, messageText) {
    if (!WHATSAPP_TOKEN || !PHONE_NUMBER_ID) {
        console.error('❌ ERROR: WHATSAPP_TOKEN or PHONE_NUMBER_ID not set.');
        return;
    }

    const url = `https://graph.facebook.com/v19.0/${PHONE_NUMBER_ID}/messages`;

    try {
        await axios.post(url, {
            messaging_product: 'whatsapp',
            recipient_type: 'individual',
            to: to, // The user's number to reply to
            type: 'text',
            text: {
                body: messageText
            }
        }, {
            headers: {
                'Authorization': `Bearer ${WHATSAPP_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });

        console.log(`✅ SENT: Automated reply sent to ${to}.`);
    } catch (error) {
        console.error('❌ FAILED TO SEND MESSAGE:', error.response ? JSON.stringify(error.response.data) : error.message);
    }
}

// Middleware to verify signature (Your existing working function)
function verifySignature(req, res, next) {
    const signatureHeader = req.header('X-Hub-Signature-256');
    const expectedPrefix = 'sha256=';
    
    if (!signatureHeader || !signatureHeader.startsWith(expectedPrefix)) {
        console.warn('Missing or invalid signature header');
        return res.sendStatus(401);
    }

    const receivedSignatureHex = signatureHeader.slice(expectedPrefix.length);
    const rawBodyBuffer = req.rawBody;
    
    // Safety check for rawBodyBuffer
    if (!rawBodyBuffer || !APP_SECRET) {
        console.error('❌ APP_SECRET or raw body is missing.');
        return res.sendStatus(500);
    }

    const hmac = crypto.createHmac('sha256', APP_SECRET);
    hmac.update(rawBodyBuffer);
    const computedDigestHex = hmac.digest('hex');

    try {
        const bufSig = Buffer.from(receivedSignatureHex, 'hex');
        const bufDigest = Buffer.from(computedDigestHex, 'hex');

        if (bufSig.length !== bufDigest.length || !crypto.timingSafeEqual(bufSig, bufDigest)) {
            console.warn('Signature did not match');
            return res.sendStatus(401);
        }
    } catch(err) {
        console.error('Error during signature comparison', err);
        return res.sendStatus(401);
    }

    console.log('✅ Signature verification passed');
    next();
}

// ---------------------------

// 2. GET route for verification handshake
app.get('/webhook', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        console.log('✅ WEBHOOK VERIFIED');
        res.status(200).send(challenge);
    } else {
        console.warn('❌ Verification failed');
        res.sendStatus(403);
    }
});

// 3. POST route for receiving webhook events (The core logic)
app.post('/webhook', verifySignature, (req, res) => {
    console.log('📬 Incoming Webhook:', JSON.stringify(req.body, null, 2));

    const body = req.body;

    // Process the message and send a reply
    if (body.object === 'whatsapp_business_account') {
        body.entry.forEach(entry => {
            entry.changes.forEach(change => {
                const value = change.value;
                const field = change.field;

                if (field === 'messages' && value.messages) {
                    value.messages.forEach(message => {
                        const from = message.from; // The user's WhatsApp ID (wa_id)
                        const incomingText = message.text?.body || 'No Text Body';
                        
                        console.log(`💬 Received: "${incomingText}" from ${from}`);

                        // --- Automated Response Logic ---
                        const replyMessage = `Hello! I see you sent: "${incomingText}". I am your Node.js automated bot. Thanks for texting!`;
                        
                        // Send the reply asynchronously (non-blocking)
                        sendTextMessage(from, replyMessage); 
                        // ---------------------------------
                    });
                }
            });
        });
    }

    // IMPORTANT: Acknowledge the webhook immediately with 200 OK.
    // The message sending process should not block this response.
    res.sendStatus(200);
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Webhook listener started on port ${PORT}`);
});


// // Dependencies
// const express = require('express');
// const crypto = require('crypto');
// const bodyParser = require('body-parser');

// const app = express();

// // Use bodyParser to capture raw body buffer (for signature verification)
// app.use(bodyParser.json({
//   verify: (req, res, buf) => {
//     // Save raw body buffer on req for later use
//     req.rawBody = buf;
//   }
// }));

// const PORT = process.env.PORT || 3000;
// const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
// const APP_SECRET  = process.env.META_APP_SECRET;     // from your Meta App Dashboard

// // GET route for verification handshake
// app.get('/webhook', (req, res) => {
//   const mode  = req.query['hub.mode'];
//   const token = req.query['hub.verify_token'];
//   const challenge = req.query['hub.challenge'];

//   if (mode === 'subscribe' && token === VERIFY_TOKEN) {
//     console.log('✅ WEBHOOK VERIFIED');
//     res.status(200).send(challenge);
//   } else {
//     console.warn('❌ Verification failed: mode=%s token=%s', mode, token);
//     res.sendStatus(403);
//   }
// });

// // Middleware to verify signature
// // function verifySignature(req, res, next) {
// //   const signatureHeader = req.header('X-Hub-Signature-256');
// //   if (!signatureHeader) {
// //     console.warn('Missing signature header');
// //     return res.sendStatus(401);
// //   }

// //   const expectedPrefix = 'sha256=';
// //   if (!signatureHeader.startsWith(expectedPrefix)) {
// //     console.warn('Invalid signature header format');
// //     return res.sendStatus(401);
// //   }

// //   const signature = signatureHeader.slice(expectedPrefix.length);
// //   const hmac = crypto.createHmac('sha256', APP_SECRET);
// //   hmac.update(req.rawBody);
// //   const digest = hmac.digest('hex');

// //   // Use timingSafeEqual for security
// //   const bufSig = Buffer.from(signature, 'hex');
// //   const bufDigest = Buffer.from(digest, 'hex');

// //   console.log('Received signature:', req.header('X-Hub-Signature-256'));
// //   console.log('Computed digest:', digest);
// //   console.log('Payload length:', req.rawBody.length);

// //   if (bufSig.length !== bufDigest.length ||
// //       !crypto.timingSafeEqual(bufSig, bufDigest)) {
// //     console.warn('Signature verification failed');
// //     return res.sendStatus(401);
// //   }

// //   // signature OK, proceed
// //   next();
// // }

// function verifySignature(req, res, next) {
//   const signatureHeader = req.header('X-Hub-Signature-256');
//   console.log('Header raw:', signatureHeader);
//   if (!signatureHeader) {
//     console.warn('Missing signature header');
//     return res.sendStatus(401);
//   }

//   const expectedPrefix = 'sha256=';
//   if (!signatureHeader.startsWith(expectedPrefix)) {
//     console.warn('Invalid signature header format:', signatureHeader);
//     return res.sendStatus(401);
//   }

//   const receivedSignatureHex = signatureHeader.slice(expectedPrefix.length);
//   const rawBodyBuffer = req.rawBody;
//   console.log('Raw body (utf8):', rawBodyBuffer.toString('utf8'));
//   console.log('Raw body (hex):', rawBodyBuffer.toString('hex').slice(0,100) + '…'); // truncated for readability
//   console.log('Raw body length:', rawBodyBuffer.length);

//   const hmac = crypto.createHmac('sha256', APP_SECRET);
//   hmac.update(rawBodyBuffer);
//   const computedDigestHex = hmac.digest('hex');
//   console.log('Computed digest hex:', computedDigestHex);

//   try {
//     const bufSig = Buffer.from(receivedSignatureHex, 'hex');
//     const bufDigest = Buffer.from(computedDigestHex, 'hex');

//     if (bufSig.length !== bufDigest.length || !crypto.timingSafeEqual(bufSig, bufDigest)) {
//       console.warn('Signature did not match');
//       return res.sendStatus(401);
//     }
//   } catch(err) {
//     console.error('Error during signature comparison', err);
//     return res.sendStatus(401);
//   }

//   console.log('✅ Signature verification passed');
//   next();
// }


// // POST route for receiving webhook events
// app.post('/webhook', verifySignature, (req, res) => {
//   console.log('📬 Incoming Webhook:', JSON.stringify(req.body, null, 2));

//   const body = req.body;

//   // Check object type
//   if (body.object === 'whatsapp_business_account') {
//     body.entry.forEach(entry => {
//       entry.changes.forEach(change => {
//         const value = change.value;
//         const field = change.field;

//         // Example: if a new message received
//         if (field === 'messages' && value.messages) {
//           value.messages.forEach(message => {
//             const from = message.from;
//             const msgBody = message.text?.body;
//             console.log(`Message from ${from}: ${msgBody}`);
//             // TODO: Process message (store, trigger response, etc.)
//           });
//         }

//         // Handle other fields (message_status, etc.)
//         if (field === 'message_statuses' && value.statuses) {
//           // Process message status updates
//         }
//       });
//     });
//   }

//   // Return 200 to acknowledge
//   res.sendStatus(200);
// });

// // Start the server
// app.listen(PORT, () => {
//   console.log(`🚀 Webhook listener started on port ${PORT}`);
// });
