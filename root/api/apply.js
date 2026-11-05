// Scholarship application capture.
//
// Flow: /scholarship form -> here -> Zapier Catch Hook -> Funnelr
// (Create/Update User + the tag and list both named "LM: Scholarship 2026").
//
// The form posts twice on a completed application:
//
//   stage: "partial"   after step 1, with contact fields only
//   stage: "complete"  on submit, with everything
//
// That is deliberate. Most people who start this form will abandon it at the
// salary questions, and a partial record is a real lead we would otherwise
// lose. Funnelr upserts on email, so the second POST updates the first rather
// than creating a duplicate - but the `stage` field is passed through so the
// Zap can route incompletes into a separate follow-up.
//
// Adapted from lead-magnets/negotiation-playbook/api/subscribe.js. The
// validation, rate limiting and honeypot behaviour are deliberately identical;
// only the field set differs.

// --- Rate limiting -----------------------------------------------------------
// Per-IP sliding window, in-memory. Resets on cold start, which is fine: it
// stops the realistic threat without the cost of an external store. The ceiling
// is higher than the lead magnets' because one genuine applicant legitimately
// hits this endpoint twice, and a shared office or campus NAT multiplies that.
const RATE_LIMIT = { max: 20, windowMs: 60 * 60 * 1000 }; // 20 / hour / IP
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
  if (rateLimits.size > 10_000) {
    rateLimits.delete(rateLimits.keys().next().value);
  }
  return { allowed: true };
}

// --- Validation --------------------------------------------------------------
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

// Deliberately permissive: real names contain apostrophes, hyphens, spaces and
// non-Latin scripts, so pattern-matching them rejects legitimate people.
const NAME_MAX = 80;
const SHORT_MAX = 200;    // titles, countries, cities, target role
const LONG_MAX = 800;     // the two free-text answers
const URL_MAX = 400;

function validateEmail(value) {
  if (typeof value !== 'string') return 'Please enter a valid email address.';
  const email = value.trim().toLowerCase();
  if (!email) return 'Please enter your email address.';
  if (email.length > 254 || !EMAIL_RE.test(email)) return 'Please enter a valid email address.';
  if (DISPOSABLE_EMAIL_DOMAINS.has(email.slice(email.lastIndexOf('@') + 1))) {
    return 'Please use a permanent email address, not a disposable inbox.';
  }
  return null;
}

// Trims, caps length, and coerces anything that is not a string to ''. Applied
// to every free-text field so a hand-rolled POST cannot push an unbounded
// payload through to Zapier.
function clean(value, max) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

// Fields required at each stage. Step 1 is all we can insist on for a partial:
// the whole point is that the applicant has not answered the rest yet.
const REQUIRED_PARTIAL = ['first_name', 'last_name', 'email', 'linkedin', 'country', 'city'];
const REQUIRED_COMPLETE = REQUIRED_PARTIAL.concat([
  'job_title', 'years_experience', 'situation', 'salary_current', 'salary_target',
  'sponsorship', 'hours', 'target_role', 'tried', 'change',
]);

const LABELS = {
  first_name: 'First name', last_name: 'Last name', email: 'Email',
  linkedin: 'LinkedIn profile URL', country: 'Country', city: 'City',
  job_title: 'Current job title', years_experience: 'Years of experience',
  situation: 'Current situation', salary_current: 'Current salary',
  salary_target: 'Target salary', sponsorship: 'Visa sponsorship',
  hours: 'Hours a week', target_role: 'Target role',
  tried: 'What have you already tried?',
  change: 'What would landing this role change for you?',
};

// --- Funnelr sync ------------------------------------------------------------
// Throws on failure so the handler can tell the applicant to try again. A
// silent failure would lose the application and show them a success screen.
//
// The env var is deliberately campaign-specific: FUNNELR_WEBHOOK_URL is a
// shared Vercel variable used by another magnet, and reusing that name would
// route these applications to the wrong Zap and tag them wrong.
async function sendToFunnelr(payload) {
  const webhookUrl = process.env.FUNNELR_SCHOLARSHIP_WEBHOOK_URL;
  if (!webhookUrl) {
    throw new Error('FUNNELR_SCHOLARSHIP_WEBHOOK_URL is not set');
  }

  const resp = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
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

  const body = req.body || {};

  // Honeypot: a real person never fills a field they cannot see. Return 200 so
  // the bot gets no signal it was caught, but skip the Funnelr write.
  if (typeof body.company === 'string' && body.company.trim() !== '') {
    return res.status(200).json({ ok: true });
  }

  const stage = body.stage === 'partial' ? 'partial' : 'complete';

  const emailError = validateEmail(body.email);
  if (emailError) return res.status(400).json({ error: emailError });

  const required = stage === 'partial' ? REQUIRED_PARTIAL : REQUIRED_COMPLETE;
  for (const key of required) {
    if (key === 'email') continue;
    if (!clean(body[key], LONG_MAX)) {
      return res.status(400).json({ error: `${LABELS[key] || key} is required.` });
    }
  }

  if (clean(body.first_name, NAME_MAX + 1).length > NAME_MAX) {
    return res.status(400).json({ error: `Please keep your name under ${NAME_MAX} characters.` });
  }

  // Documentation consent gates eligibility, not submission — someone who
  // unticks it in devtools should still reach us, flagged, rather than being
  // silently dropped. Judging enforces it; see the campaign spec.
  const consentDocs = body.consent_docs === true;

  // There is no marketing tickbox: every applicant is added to the list, and the
  // form states that above the submit button. The basis is recorded on the
  // record rather than assumed, so that if the wording on the page ever changes
  // it is possible to tell which applicants saw which version.
  const MARKETING_BASIS = 'notice-at-application-2026-08';

  const ip = getClientIp(req);
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    res.setHeader('Retry-After', rl.retryAfter);
    const minutes = Math.max(1, Math.ceil(rl.retryAfter / 60));
    return res.status(429).json({
      error: `Too many submissions from this network. Please try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
    });
  }

  const email = body.email.trim().toLowerCase();
  const utm = (body.utm && typeof body.utm === 'object') ? body.utm : {};

  const payload = {
    email,
    first_name: clean(body.first_name, NAME_MAX),
    last_name: clean(body.last_name, NAME_MAX),
    linkedin: clean(body.linkedin, URL_MAX),
    country: clean(body.country, SHORT_MAX),
    city: clean(body.city, SHORT_MAX),

    job_title: clean(body.job_title, SHORT_MAX),
    years_experience: clean(body.years_experience, SHORT_MAX),
    situation: clean(body.situation, SHORT_MAX),
    salary_current: clean(body.salary_current, SHORT_MAX),
    salary_target: clean(body.salary_target, SHORT_MAX),
    sponsorship: clean(body.sponsorship, SHORT_MAX),
    hours: clean(body.hours, SHORT_MAX),

    target_role: clean(body.target_role, SHORT_MAX),
    tried: clean(body.tried, LONG_MAX),
    change: clean(body.change, LONG_MAX),
    video: clean(body.video, URL_MAX),

    consent_documentation: consentDocs,
    marketing_basis: MARKETING_BASIS,

    stage,
    source: 'Scholarship 2026',
    tag: 'LM: Scholarship 2026',
    utm_source: clean(utm.utm_source, SHORT_MAX),
    utm_medium: clean(utm.utm_medium, SHORT_MAX),
    utm_campaign: clean(utm.utm_campaign, SHORT_MAX),
    utm_content: clean(utm.utm_content, SHORT_MAX),
    coach: clean(utm.coach, SHORT_MAX),
    referrer: clean(utm.referrer, URL_MAX),
    captured_at: new Date().toISOString(),
  };

  try {
    await sendToFunnelr(payload);
  } catch (err) {
    console.error('[SCHOLARSHIP] Funnelr sync failed:', err);
    return res.status(502).json({
      error: 'We could not save your application. Please try again in a moment.',
    });
  }

  console.log(`[SCHOLARSHIP] ${email} | ${stage} | ${payload.country} | ${new Date().toISOString()}`);

  return res.status(200).json({ ok: true });
}
