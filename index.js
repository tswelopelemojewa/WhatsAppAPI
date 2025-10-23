// Dependencies
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();

// Use bodyParser to capture raw body buffer (for signature verification)
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    // Save raw body buffer on req for later use
    req.rawBody = buf;
  }
}));

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
const APP_SECRET  = process.env.META_APP_SECRET;     // from your Meta App Dashboard

// GET route for verification handshake
app.get('/webhook', (req, res) => {
  const mode  = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    console.warn('❌ Verification failed: mode=%s token=%s', mode, token);
    res.sendStatus(403);
  }
});

// Middleware to verify signature
function verifySignature(req, res, next) {
  const signatureHeader = req.header('X-Hub-Signature-256');
  if (!signatureHeader) {
    console.warn('Missing signature header');
    return res.sendStatus(401);
  }

  const expectedPrefix = 'sha256=';
  if (!signatureHeader.startsWith(expectedPrefix)) {
    console.warn('Invalid signature header format');
    return res.sendStatus(401);
  }

  const signature = signatureHeader.slice(expectedPrefix.length);
  const hmac = crypto.createHmac('sha256', APP_SECRET);
  hmac.update(req.rawBody);
  const digest = hmac.digest('hex');

  // Use timingSafeEqual for security
  const bufSig = Buffer.from(signature, 'hex');
  const bufDigest = Buffer.from(digest, 'hex');

  console.log('Received signature:', req.header('X-Hub-Signature-256'));
  console.log('Computed digest:', digest);
  console.log('Payload length:', req.rawBody.length);

  if (bufSig.length !== bufDigest.length ||
      !crypto.timingSafeEqual(bufSig, bufDigest)) {
    console.warn('Signature verification failed');
    return res.sendStatus(401);
  }

  // signature OK, proceed
  next();
}

// POST route for receiving webhook events
app.post('/webhook', verifySignature, (req, res) => {
  console.log('📬 Incoming Webhook:', JSON.stringify(req.body, null, 2));

  const body = req.body;

  // Check object type
  if (body.object === 'whatsapp_business_account') {
    body.entry.forEach(entry => {
      entry.changes.forEach(change => {
        const value = change.value;
        const field = change.field;

        // Example: if a new message received
        if (field === 'messages' && value.messages) {
          value.messages.forEach(message => {
            const from = message.from;
            const msgBody = message.text?.body;
            console.log(`Message from ${from}: ${msgBody}`);
            // TODO: Process message (store, trigger response, etc.)
          });
        }

        // Handle other fields (message_status, etc.)
        if (field === 'message_statuses' && value.statuses) {
          // Process message status updates
        }
      });
    });
  }

  // Return 200 to acknowledge
  res.sendStatus(200);
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Webhook listener started on port ${PORT}`);
});
