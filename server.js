require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// ===================== MIDDLEWARE =====================
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'محاولات كثيرة. انتظر 15 دقيقة وحاول مجدداً.' }
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { error: 'تم إرسال الحد الأقصى من الإيميلات. انتظر ساعة.' }
});

// ===================== DATABASE =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Create tables
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        platform VARCHAR(20) NOT NULL DEFAULT 'email',
        username VARCHAR(100),
        is_verified BOOLEAN DEFAULT FALSE,
        is_admin BOOLEAN DEFAULT FALSE,
        points INTEGER DEFAULT 0,
        level VARCHAR(50) DEFAULT 'مبتدئ',
        subscription VARCHAR(20) DEFAULT 'inactive',
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP,
        kick_username VARCHAR(100)
      );

      CREATE TABLE IF NOT EXISTS verification_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(6) NOT NULL,
        type VARCHAR(20) NOT NULL DEFAULT 'verify',
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(500) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL
      );
    `);
    console.log('✅ Database tables initialized');

    // Create admin user if not exists
    const adminEmail = process.env.ADMIN_EMAIL || 'ooiyt980@gmail.com';
    const existing = await client.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash('Admin@123', 12);
      await client.query(
        `INSERT INTO users (email, password_hash, username, is_verified, is_admin, platform)
         VALUES ($1, $2, $3, TRUE, TRUE, 'email')`,
        [adminEmail, hash, 'Admin']
      );
      console.log('✅ Admin user created');
    }
  } finally {
    client.release();
  }
}

// ===================== EMAIL =====================

async function sendVerificationEmail(email, username, code, type = 'verify') {
  const isVerify = type === 'verify';
  const subject = isVerify ? '🎯 كود تفعيل حسابك — طقّه والحقّه' : '🔐 كود تسجيل الدخول — طقّه والحقّه';

  const html = `
<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background:#0A0A0F;font-family:'Segoe UI',Tahoma,Arial,sans-serif;">
  <div style="max-width:520px;margin:0 auto;padding:32px 16px;">

    <!-- Header -->
    <div style="text-align:center;margin-bottom:32px;">
      <div style="display:inline-flex;align-items:center;gap:10px;background:#111118;border:1px solid rgba(245,200,66,0.2);border-radius:12px;padding:12px 24px;">
        <span style="font-size:1.4rem;">🎯</span>
        <span style="color:#F5C842;font-weight:800;font-size:1.2rem;">طقّه والحقّه</span>
      </div>
    </div>

    <!-- Card -->
    <div style="background:#111118;border:1px solid rgba(245,200,66,0.15);border-radius:20px;overflow:hidden;">

      <!-- Top bar -->
      <div style="height:3px;background:linear-gradient(90deg,#F5C842,#E8334A);"></div>

      <div style="padding:36px 32px;">
        <h1 style="color:#FFFFFF;font-size:1.5rem;font-weight:800;margin:0 0 8px 0;">
          ${isVerify ? 'مرحباً ' + (username || '') + '! 👋' : 'كود تسجيل الدخول 🔐'}
        </h1>
        <p style="color:rgba(255,255,255,0.5);font-size:0.95rem;margin:0 0 32px 0;line-height:1.7;">
          ${isVerify
            ? 'شكراً لتسجيلك في منصة طقّه والحقّه. أدخل الكود أدناه لتفعيل حسابك.'
            : 'تم طلب تسجيل دخول لحسابك. أدخل الكود أدناه للمتابعة.'}
        </p>

        <!-- OTP Code -->
        <div style="background:#0A0A0F;border:1px solid rgba(245,200,66,0.25);border-radius:16px;padding:28px;text-align:center;margin-bottom:28px;">
          <div style="color:rgba(255,255,255,0.4);font-size:0.75rem;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">الكود السري</div>
          <div style="font-size:3rem;font-weight:900;letter-spacing:16px;color:#F5C842;font-family:'Courier New',monospace;">${code}</div>
          <div style="color:rgba(255,255,255,0.3);font-size:0.78rem;margin-top:12px;">⏱️ صالح لمدة 10 دقائق فقط</div>
        </div>

        <!-- Warning -->
        <div style="background:rgba(232,51,74,0.08);border:1px solid rgba(232,51,74,0.2);border-radius:10px;padding:14px 18px;margin-bottom:24px;">
          <p style="color:rgba(255,255,255,0.6);font-size:0.82rem;margin:0;line-height:1.6;">
            🔒 <strong style="color:#E8334A;">تنبيه:</strong> لا تشارك هذا الكود مع أي شخص. فريق طقّه والحقّه لن يطلب منك الكود أبداً.
          </p>
        </div>

        <p style="color:rgba(255,255,255,0.35);font-size:0.8rem;margin:0;line-height:1.6;">
          إذا لم تطلب هذا الكود، تجاهل هذا الإيميل بأمان.
        </p>
      </div>

      <!-- Footer -->
      <div style="background:rgba(255,255,255,0.02);border-top:1px solid rgba(255,255,255,0.06);padding:20px 32px;text-align:center;">
        <p style="color:rgba(255,255,255,0.2);font-size:0.78rem;margin:0;">© 2025 طقّه والحقّه — منصة الألعاب التفاعلية</p>
      </div>
    </div>
  </div>
</body>
</html>`;

  await resend.emails.send({
    from: 'طقّه والحقّه <onboarding@resend.dev>',
    to: email,
    subject,
    html
  });
}

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ===================== AUTH MIDDLEWARE =====================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'جلسة منتهية، سجّل دخولك مجدداً' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'صلاحيات غير كافية' });
  next();
}

// ===================== ROUTES =====================

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date() }));

// --- REGISTER ---
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, username, platform = 'email', kickUsername } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'الإيميل وكلمة المرور مطلوبان' });
  if (password.length < 8) return res.status(400).json({ error: 'كلمة المرور 8 أحرف على الأقل' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'إيميل غير صحيح' });

  const client = await pool.connect();
  try {
    const existing = await client.query('SELECT id, is_verified FROM users WHERE email = $1', [email.toLowerCase()]);

    if (existing.rows.length > 0) {
      if (!existing.rows[0].is_verified) {
        // Resend verification
        const otp = generateOTP();
        await client.query('DELETE FROM verification_tokens WHERE user_id = $1 AND type = $2', [existing.rows[0].id, 'verify']);
        await client.query(
          'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
          [existing.rows[0].id, otp, 'verify']
        );
        await sendVerificationEmail(email, username, otp, 'verify');
        return res.json({ success: true, message: 'تم إعادة إرسال كود التحقق', needsVerification: true });
      }
      return res.status(409).json({ error: 'هذا الإيميل مسجّل مسبقاً' });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await client.query(
      `INSERT INTO users (email, password_hash, username, platform, kick_username, is_admin)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [email.toLowerCase(), hash, username || email.split('@')[0], platform, kickUsername || null,
       email.toLowerCase() === 'ooiyt980@gmail.com']
    );

    const userId = result.rows[0].id;
    const otp = generateOTP();
    await client.query(
      'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
      [userId, otp, 'verify']
    );

    await sendVerificationEmail(email, username, otp, 'verify');

    res.json({ success: true, message: 'تم التسجيل! تحقق من إيميلك للكود', needsVerification: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'خطأ في السيرفر. حاول مجدداً.' });
  } finally {
    client.release();
  }
});

// --- VERIFY OTP ---
app.post('/api/auth/verify-otp', authLimiter, async (req, res) => {
  const { email, otp, type = 'verify' } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'الإيميل والكود مطلوبان' });

  const client = await pool.connect();
  try {
    const userRes = await client.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!userRes.rows.length) return res.status(404).json({ error: 'الإيميل غير موجود' });
    const user = userRes.rows[0];

    const tokenRes = await client.query(
      'SELECT * FROM verification_tokens WHERE user_id = $1 AND type = $2 AND used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [user.id, type]
    );

    if (!tokenRes.rows.length) return res.status(400).json({ error: 'الكود منتهي أو غير صحيح. اطلب كود جديد.' });

    const tokenRow = tokenRes.rows[0];
    if (tokenRow.token !== otp.trim()) return res.status(400).json({ error: 'كود خاطئ. تحقق من إيميلك.' });

    // Mark token used
    await client.query('UPDATE verification_tokens SET used = TRUE WHERE id = $1', [tokenRow.id]);

    if (type === 'verify') {
      await client.query('UPDATE users SET is_verified = TRUE WHERE id = $1', [user.id]);
    }

    // Update last login
    await client.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // Generate JWT
    const jwtToken = jwt.sign(
      { id: user.id, email: user.email, username: user.username, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Save session
    await client.query(
      'INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'7 days\')',
      [user.id, jwtToken]
    );

    res.json({
      success: true,
      token: jwtToken,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        platform: user.platform,
        is_admin: user.is_admin,
        points: user.points,
        level: user.level,
        subscription: user.subscription
      }
    });
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  } finally {
    client.release();
  }
});

// --- LOGIN (sends OTP) ---
app.post('/api/auth/login', authLimiter, emailLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'الإيميل وكلمة المرور مطلوبان' });

  const client = await pool.connect();
  try {
    const userRes = await client.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!userRes.rows.length) return res.status(401).json({ error: 'الإيميل أو كلمة المرور غير صحيحة' });

    const user = userRes.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'الإيميل أو كلمة المرور غير صحيحة' });

    if (!user.is_verified) {
      return res.status(403).json({ error: 'الحساب غير مفعّل. تحقق من إيميلك أو اطلب كود جديد.', needsVerification: true });
    }

    // Send OTP for 2FA login
    const otp = generateOTP();
    await client.query('DELETE FROM verification_tokens WHERE user_id = $1 AND type = $2', [user.id, 'login']);
    await client.query(
      'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
      [user.id, otp, 'login']
    );

    await sendVerificationEmail(email, user.username, otp, 'login');

    res.json({ success: true, message: 'تم إرسال كود التحقق لإيميلك', needsOTP: true });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  } finally {
    client.release();
  }
});

// --- RESEND OTP ---
app.post('/api/auth/resend-otp', emailLimiter, async (req, res) => {
  const { email, type = 'verify' } = req.body;
  if (!email) return res.status(400).json({ error: 'الإيميل مطلوب' });

  const client = await pool.connect();
  try {
    const userRes = await client.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!userRes.rows.length) return res.status(404).json({ error: 'الإيميل غير موجود' });
    const user = userRes.rows[0];

    const otp = generateOTP();
    await client.query('DELETE FROM verification_tokens WHERE user_id = $1 AND type = $2', [user.id, type]);
    await client.query(
      'INSERT INTO verification_tokens (user_id, token, type, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'10 minutes\')',
      [user.id, otp, type]
    );

    await sendVerificationEmail(email, user.username, otp, type);
    res.json({ success: true, message: 'تم إعادة الإرسال! تحقق من إيميلك.' });
  } catch (err) {
    console.error('Resend error:', err);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  } finally {
    client.release();
  }
});

// --- GET ME ---
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      'SELECT id, email, username, platform, is_admin, points, level, subscription, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ user: result.rows[0] });
  } finally {
    client.release();
  }
});

// --- LOGOUT ---
app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
  res.json({ success: true });
});

// ===================== ADMIN ROUTES =====================

// Get all users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { search } = req.query;
  let query = 'SELECT id, email, username, platform, points, level, subscription, is_verified, is_admin, created_at, last_login, kick_username FROM users';
  const params = [];
  if (search) {
    query += ' WHERE email ILIKE $1 OR username ILIKE $1';
    params.push(`%${search}%`);
  }
  query += ' ORDER BY points DESC';
  const result = await pool.query(query, params);
  res.json({ users: result.rows });
});

// Toggle subscription
app.patch('/api/admin/users/:id/subscription', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const result = await pool.query(
    `UPDATE users SET subscription = CASE WHEN subscription = 'active' THEN 'inactive' ELSE 'active' END WHERE id = $1 RETURNING subscription, username`,
    [id]
  );
  if (!result.rows.length) return res.status(404).json({ error: 'المستخدم غير موجود' });
  res.json({ success: true, subscription: result.rows[0].subscription, username: result.rows[0].username });
});

// Bulk toggle
app.patch('/api/admin/users/bulk/subscription', authMiddleware, adminMiddleware, async (req, res) => {
  const { status } = req.body;
  if (!['active', 'inactive'].includes(status)) return res.status(400).json({ error: 'حالة غير صحيحة' });
  await pool.query('UPDATE users SET subscription = $1 WHERE is_admin = FALSE', [status]);
  res.json({ success: true });
});

// Get stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  const stats = await pool.query(`
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE subscription = 'active') AS active,
      COUNT(*) FILTER (WHERE subscription = 'inactive') AS inactive,
      COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') AS new_this_month
    FROM users WHERE is_admin = FALSE
  `);
  res.json(stats.rows[0]);
});

// ===================== START =====================
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Gmail: ${process.env.GMAIL_USER}`);
    console.log(`🗄️  Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
  });
}).catch(err => {
  console.error('Failed to initialize DB:', err);
  process.exit(1);
});
