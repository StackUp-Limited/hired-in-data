// Lead-magnet email capture for the pages served under hiredindata.com.
//
// Flow: magnet opt-in page -> here -> Zapier Catch Hook -> Funnelr
// (Create/Update User + the tag and list both named "LM: <Magnet Name>").
// Funnelr's automation sends the delivery email containing the resource link.
// The browser redirects straight to the resource on a 200, so the reader never
// waits on the email.
//
// The resource itself stays a plain static page with no gate on it. That is
// deliberate: the delivery email needs a permanent link that works without the
// form. The gate is a speed bump, not access control.
//
// Adapted from lead-magnets/negotiation-playbook/api/subscribe.js. Validation,
// rate limiting and honeypot behaviour are deliberately identical; the one
// difference is that this endpoint is shared by every magnet on the domain and
// routes on the `magnet` field below.

// --- Magnet registry ---------------------------------------------------------
// One entry per gated magnet on this domain. The webhook env var is
// deliberately per-magnet: FUNNELR_WEBHOOK_URL is a Vercel *shared* variable
// used by the headline analyzer, and reusing that name would route these leads
// to the analyzer's Zap and tag them wrong. An unknown `magnet` is rejected
// rather than defaulted, so a typo on a page surfaces as an error instead of
// silently tagging leads as something else.
const MAGNETS = {
  'real-interview-questions': {
    source: 'Real Interview Questions',
    tag: 'LM: Real Interview Questions',
    envVar: 'FUNNELR_REAL_INTERVIEW_QUESTIONS_WEBHOOK_URL',
  },
  'faang-cheat-sheet': {
    source: 'FAANG Cheat Sheet',
    tag: 'LM: FAANG Cheat Sheet',
    envVar: 'FUNNELR_FAANG_CHEAT_SHEET_WEBHOOK_URL',
  },
  'unicorn-cheat-sheet': {
    source: 'Unicorn Cheat Sheet',
    tag: 'LM: Unicorn Cheat Sheet',
    envVar: 'FUNNELR_UNICORN_CHEAT_SHEET_WEBHOOK_URL',
  },
  'ai-cheat-sheet': {
    source: 'AI Cheat Sheet',
    tag: 'LM: AI Cheat Sheet',
    envVar: 'FUNNELR_AI_CHEAT_SHEET_WEBHOOK_URL',
  },
};

// --- Rate limiting -----------------------------------------------------------
// Per-IP sliding window, in-memory. Resets on cold start, which is fine: it
// stops the realistic threat (someone hammering the form) without the cost of
// an external store.
const RATE_LIMIT = { max: 10, windowMs: 60 * 60 * 1000 }; // 10 / hour / IP
const rateLimits = new Map();

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) {
    return fwd.split(',')[0].trim();
  }
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'anon';
}

function checkRateLimit(ip) {
  const now = Date.now();
  const cutoff = now - RATE_LIMIT.windowMs;
  const hits = (rateLimits.get(ip) || []).filter((t) => t > cutoff);
  if (hits.length >= RATE_LIMIT.max) {
    const retryAfter = Math.ceil((hits[0] + RATE_LIMIT.windowMs - now) / 1000);
    return { allowed: false, retryAfter };
  }
  hits.push(now);
  rateLimits.set(ip, hits);
  // Bound memory: drop the oldest-inserted IP when the map gets large.
  if (rateLimits.size > 10_000) {
    rateLimits.delete(rateLimits.keys().next().value);
  }
  return { allowed: true };
}

// --- Email validation --------------------------------------------------------
// Format check plus a blocklist of common disposable-inbox domains. The list is
// not exhaustive - new throwaway domains appear constantly - it just stops the
// obvious ones. Kept in sync with the copy in the other magnets.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const DISPOSABLE_EMAIL_DOMAINS = new Set([
  '10minutemail.com', '20minutemail.com', '33mail.com', 'discard.email',
  'dispostable.com', 'emailondeck.com', 'fakeinbox.com', 'getairmail.com',
  'getnada.com', 'guerrillamail.com', 'guerrillamailblock.com', 'mailcatch.com',
  'maildrop.cc', 'mailinator.com', 'mailnesia.com', 'mintemail.com', 'moakt.com',
  'mohmal.com', 'mvrht.com', 'mytemp.email', 'nada.email', 'sharklasers.com',
  'spam4.me', 'spamgourmet.com', 'temp-mail.org', 'tempinbox.com',
  'tempmail.com', 'tempmailo.com', 'throwawaymail.com', 'tmpeml.com',
  'tmpmail.org', 'trashmail.com', 'trashmail.de', 'yopmail.com', 'yopmail.fr',
]);

// --- Name validation ---------------------------------------------------------
// Deliberately permissive. Real names contain apostrophes, hyphens, spaces and
// non-Latin scripts, so pattern-matching them rejects legitimate people. Only
// presence and a length cap are enforced.
const NAME_MAX = 80;

function validateName(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return { valid: false, error: 'Please enter your first name.' };
  }
  if (value.trim().length > NAME_MAX) {
    return { valid: false, error: `Please keep your name under ${NAME_MAX} characters.` };
  }
  return { valid: true, error: null };
}

// Returns { valid, error } - error is a user-facing message when invalid.
function validateEmail(value) {
  if (typeof value !== 'string') {
    return { valid: false, error: 'Please enter a valid email address.' };
  }
  const email = value.trim().toLowerCase();
  if (!email) {
    return { valid: false, error: 'Please enter your email address.' };
  }
  if (email.length > 254 || !EMAIL_RE.test(email)) {
    return { valid: false, error: 'Please enter a valid email address.' };
  }
  const domain = email.slice(email.lastIndexOf('@') + 1);
  if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    return { valid: false, error: 'Please use a permanent email address, not a disposable inbox.' };
  }
  return { valid: true, error: null };
}

// --- Funnelr sync ------------------------------------------------------------
// Throws on failure so the handler can tell the reader to try again. The email
// IS the whole transaction here - a silent failure would lose the lead and send
// them to the resource as if nothing was wrong.
async function sendToFunnelr(magnet, email, firstName) {
  const webhookUrl = process.env[magnet.envVar];
  if (!webhookUrl) {
    throw new Error(`${magnet.envVar} is not set`);
  }

  const resp = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      first_name: firstName,
      source: magnet.source,
      tag: magnet.tag,
      captured_at: new Date().toISOString(),
    }),
  });

  if (!resp.ok) {
    throw new Error(`Zapier webhook returned ${resp.status}`);
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { magnet: magnetKey, email, first_name: firstName, company } = req.body || {};

  const magnet = MAGNETS[magnetKey];
  if (!magnet) {
    // A reader can never cause this - it means the page posted the wrong key.
    console.error('[SUBSCRIBE] unknown magnet:', magnetKey);
    return res.status(400).json({ error: 'Something went wrong. Please try again.' });
  }

  // Honeypot: a real person never fills a field they cannot see. Return 200 so
  // the bot gets no signal that it was caught, but skip the Funnelr write.
  if (typeof company === 'string' && company.trim() !== '') {
    return res.status(200).json({ ok: true });
  }

  // Name first, matching the field order on the page, so the error the reader
  // sees points at the field they actually need to fix.
  const nameCheck = validateName(firstName);
  if (!nameCheck.valid) {
    return res.status(400).json({ error: nameCheck.error });
  }

  const emailCheck = validateEmail(email);
  if (!emailCheck.valid) {
    return res.status(400).json({ error: emailCheck.error });
  }

  const ip = getClientIp(req);
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    res.setHeader('Retry-After', rl.retryAfter);
    const minutes = Math.max(1, Math.ceil(rl.retryAfter / 60));
    return res.status(429).json({
      error: `Too many submissions from this network. Please try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
    });
  }

  const sanitizedEmail = email.trim().toLowerCase();
  const sanitizedName = firstName.trim();

  try {
    await sendToFunnelr(magnet, sanitizedEmail, sanitizedName);
  } catch (err) {
    console.error('[SUBSCRIBE] Funnelr sync failed:', err);
    return res.status(502).json({
      error: 'We could not save your email. Please try again in a moment.',
    });
  }

  console.log(`[EMAIL_CAPTURE] ${sanitizedEmail} | ${sanitizedName} | ${magnetKey} | ${new Date().toISOString()}`);

  return res.status(200).json({ ok: true });
}
