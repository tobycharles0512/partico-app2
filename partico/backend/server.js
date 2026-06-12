const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const WebSocket = require('ws');
const cors = require('cors');
require('dotenv').config();

const app = express();
// Only allow the Partico frontend (plus local dev) to call this API
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || origin === 'null') return cb(null, true); // curl, native apps, local file previews
    try {
      const { hostname } = new URL(origin);
      if (
        hostname === 'partico.app' ||
        hostname.endsWith('.partico.app') ||
        hostname.endsWith('.vercel.app') ||
        hostname === 'localhost' ||
        hostname === '127.0.0.1'
      ) return cb(null, true);
    } catch (e) {}
    return cb(null, false);
  }
}));
app.use(express.json({ limit: '5mb' }));

// Simple in-memory rate limiter for auth endpoints (per IP per path)
const rateBuckets = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    if (rateBuckets.size > 10000) rateBuckets.clear();
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
    const key = `${req.path}:${ip}`;
    const now = Date.now();
    let bucket = rateBuckets.get(key);
    if (!bucket || now - bucket.start > windowMs) {
      bucket = { start: now, count: 0 };
      rateBuckets.set(key, bucket);
    }
    bucket.count++;
    if (bucket.count > max) {
      return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
    }
    next();
  };
}

// Supabase client
let supabase = null;
let supabaseInitError = null;
try {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    supabaseInitError = 'Env vars not set';
    console.error('WARNING: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set');
  } else {
    supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      { auth: { persistSession: false, autoRefreshToken: false }, realtime: { transport: WebSocket } }
    );
    console.log('Supabase client initialized, URL:', process.env.SUPABASE_URL.substring(0, 40));
  }
} catch (err) {
  supabaseInitError = err.message;
  console.error('Supabase init error:', err.message);
}

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const RESEND_API_KEY = process.env.RESEND_API_KEY;

// Helper: Generate 6-digit verification code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: Send email via Resend
async function sendEmail(to, subject, html) {
  console.log('[sendEmail] Resend API key configured:', !!RESEND_API_KEY);

  if (!RESEND_API_KEY) {
    console.log(`[Mock Email] To: ${to}, Subject: ${subject}`);
    return true;
  }

  try {
    console.log('[sendEmail] Sending email via Resend to:', to);
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'noreply@partico.app',
        to,
        subject,
        html,
      }),
    });

    console.log('[sendEmail] Resend response status:', response.status);
    const resendData = await response.json();
    console.log('[sendEmail] Resend response:', JSON.stringify(resendData));

    return response.ok;
  } catch (error) {
    console.error('[sendEmail] Email send error:', error.message);
    console.error('[sendEmail] Error details:', error);
    return false;
  }
}

// Signup: Send verification email
app.post('/api/auth/signup', rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  try {
    console.log('=== SIGNUP REQUEST RECEIVED ===');
    console.log('Timestamp:', new Date().toISOString());
    console.log('Request body keys:', Object.keys(req.body));

    // Check if Supabase is configured
    console.log('SUPABASE_URL configured:', !!process.env.SUPABASE_URL);
    console.log('SUPABASE_URL value:', process.env.SUPABASE_URL ? process.env.SUPABASE_URL.substring(0, 20) + '...' : 'NOT SET');

    if (!process.env.SUPABASE_URL || process.env.SUPABASE_URL.includes('placeholder')) {
      console.error('Supabase not configured - SUPABASE_URL missing or placeholder');
      return res.status(500).json({ error: 'Server configuration error. Please contact support.' });
    }

    const { email, username, firstName, lastName, phone, password } = req.body;
    console.log('Received:', { email, username, passwordLength: password ? password.length : 0, firstName, lastName, phone });

    if (!email || !password || !username) {
      return res.status(400).json({ error: 'Email, username, and password required' });
    }

    // Check if email already exists
    console.log('Checking if email already exists:', email.toLowerCase());
    const { data: existingEmail, error: emailCheckError } = await supabase
      .from('partico_users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    console.log('Email check result:', { existingEmail: !!existingEmail, errorCode: emailCheckError?.code, errorMessage: emailCheckError?.message });

    if (emailCheckError && emailCheckError.code !== 'PGRST116') {
      console.error('Email check error (code !== PGRST116):', emailCheckError);
      return res.status(500).json({ error: 'Database error. Please try again later.' });
    }

    if (existingEmail) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if username already exists
    console.log('Checking if username already exists:', username.toLowerCase());
    const { data: existingUsername, error: usernameCheckError } = await supabase
      .from('partico_users')
      .select('id')
      .eq('username', username.toLowerCase())
      .single();

    console.log('Username check result:', { existingUsername: !!existingUsername, errorCode: usernameCheckError?.code, errorMessage: usernameCheckError?.message });

    if (usernameCheckError && usernameCheckError.code !== 'PGRST116') {
      console.error('Username check error (code !== PGRST116):', usernameCheckError);
      return res.status(500).json({ error: 'Database error. Please try again later.' });
    }

    if (existingUsername) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Generate verification code
    const code = generateVerificationCode();
    console.log('Generated verification code');

    // Delete any existing verification requests for this email (to allow resend)
    console.log('Deleting existing verification requests for email');
    const { error: deleteError } = await supabase
      .from('partico_verification_requests')
      .delete()
      .eq('email', email.toLowerCase());

    if (deleteError) {
      console.error('Error deleting old requests:', deleteError);
    } else {
      console.log('Successfully deleted old requests');
    }

    // Store verification request
    const hashedPassword = await bcryptjs.hash(password, 10);
    const verificationData = {
      email: email.toLowerCase(),
      username: username.toLowerCase(),
      code,
      password: hashedPassword,
      type: 'signup',
      expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(), // 15 min expiry
    };

    // Only include optional fields if provided
    if (firstName) verificationData.firstName = firstName;
    if (lastName) verificationData.lastName = lastName;
    if (phone) verificationData.phone = phone;

    console.log('Attempting to insert verification request');
    console.log('Verification data keys:', Object.keys(verificationData));

    const { error: verifyError } = await supabase
      .from('partico_verification_requests')
      .insert([verificationData]);

    if (verifyError) {
      console.error('Verification insert error:', JSON.stringify(verifyError, null, 2));
      console.error('Error code:', verifyError?.code);
      console.error('Error message:', verifyError?.message);
      console.error('Error details:', verifyError?.details);
      return res.status(500).json({ error: 'Failed to create verification request. Please try again later.' });
    }

    console.log('Successfully inserted verification request');

    // Send verification email
    const emailHtml = `
      <div style="text-align: center; background: #0d0d0d; padding: 40px 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #fff;">
        <img src="https://res.cloudinary.com/dvrrwjm9f/image/upload/v1773603152/final_logo_myxdg2.png" alt="Partico" style="width: 100px; height: 100px; margin-bottom: 20px;">
        <h2 style="color: #00ff41; margin: 20px 0;">Verify your Partico account</h2>
        <p style="color: rgba(255,255,255,0.7); margin: 15px 0;">Your verification code is:</p>
        <h1 style="font-size: 48px; font-weight: bold; color: #00ff41; letter-spacing: 4px; margin: 30px 0;">${code}</h1>
        <p style="color: rgba(255,255,255,0.5); margin: 15px 0;">This code expires in 15 minutes.</p>
      </div>
    `;

    console.log('Attempting to send verification email to:', email);
    const emailSent = await sendEmail(email, 'Verify your Partico account', emailHtml);
    console.log('Email send result:', emailSent);

    res.json({ message: 'Verification email sent', email });
  } catch (error) {
    console.error('=== SIGNUP ERROR ===');
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Full error:', JSON.stringify(error, null, 2));
    if (error.message && error.message.includes('ENOTFOUND')) {
      res.status(500).json({ error: 'Server connection error. Please try again later.' });
    } else {
      res.status(500).json({ error: 'Signup failed. Please try again later.' });
    }
  }
});

// Verify signup: Confirm code and create account
app.post('/api/auth/verify-signup', rateLimit(20, 15 * 60 * 1000), async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    // Get verification request
    const { data: verifyRequest, error: queryError } = await supabase
      .from('partico_verification_requests')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('code', code)
      .eq('type', 'signup')
      .single();

    if (queryError || !verifyRequest) {
      console.error('Query error or request not found:', queryError);
      return res.status(400).json({ error: 'Invalid or expired verification code' });
    }

    // Check expiry
    if (new Date(verifyRequest.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Verification code expired' });
    }

    // Password was already hashed at signup time (never stored in plaintext)
    const hashedPassword = verifyRequest.password;

    // Create user
    const userId = Math.random().toString(36).substring(7); // Generate simple ID
    console.log('Attempting to create user:', { userId, email: email.toLowerCase(), username: verifyRequest.username, timestamp: new Date().toISOString() });

    const newUserRow = {
      id: userId,
      email: email.toLowerCase(),
      username: verifyRequest.username,
      password: hashedPassword,
    };
    if (verifyRequest.firstName) newUserRow.firstName = verifyRequest.firstName;
    if (verifyRequest.lastName) newUserRow.lastName = verifyRequest.lastName;
    if (verifyRequest.phone) newUserRow.phone = verifyRequest.phone;

    const insertResponse = await supabase
      .from('partico_users')
      .insert([newUserRow]);

    const { error: createError, data: insertData } = insertResponse;

    console.log('=== INSERT RESPONSE ===');
    console.log('Error:', createError ? JSON.stringify(createError, null, 2) : 'null');
    console.log('Data:', JSON.stringify(insertData, null, 2));

    if (createError) {
      console.error('=== USER CREATION ERROR ===');
      console.error('Error code:', createError?.code);
      console.error('Error message:', createError?.message);
      console.error('Error details:', createError?.details);
      console.error('Full error:', JSON.stringify(createError, null, 2));
      return res.status(500).json({ error: 'Failed to create account' });
    }

    // CRITICAL: Verify the insert actually persisted to database
    console.log('=== VERIFYING USER PERSISTED TO DATABASE ===');
    const { data: verifyUser, error: verifyError } = await supabase
      .from('partico_users')
      .select('id, email, username')
      .eq('id', userId)
      .single();

    console.log('Verification query - Error:', verifyError ? JSON.stringify(verifyError, null, 2) : 'null');
    console.log('Verification query - User found:', verifyUser ? JSON.stringify(verifyUser, null, 2) : 'null');

    if (verifyError || !verifyUser) {
      console.error('=== CRITICAL: USER NOT FOUND AFTER INSERT ===');
      console.error('Attempted to create user with ID:', userId);
      console.error('But could not read it back from database');
      console.error('Verify error:', verifyError);
    } else {
      console.log('User created successfully and verified in database');
    }

    // Delete verification request
    await supabase
      .from('partico_verification_requests')
      .delete()
      .eq('email', email.toLowerCase())
      .eq('code', code);

    // Generate JWT
    const token = jwt.sign(
      { id: userId, email: email.toLowerCase(), username: verifyRequest.username },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: userId,
        email: email.toLowerCase(),
        username: verifyRequest.username,
        firstName: verifyRequest.firstName || '',
        lastName: verifyRequest.lastName || '',
        phone: verifyRequest.phone || '',
      },
    });
  } catch (error) {
    console.error('Verify signup error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Login (with username or email)
app.post('/api/auth/login', rateLimit(20, 15 * 60 * 1000), async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({ error: 'Email/username and password required' });
    }

    // Try to find user by email or username
    const normalizedInput = emailOrUsername.toLowerCase();

    const { data: user, error: queryError } = await supabase
      .from('partico_users')
      .select('*')
      .or(`email.eq.${normalizedInput},username.eq.${normalizedInput}`)
      .single();

    if (queryError || !user) {
      console.error('User query error:', queryError);
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    // Compare password
    const passwordMatch = await bcryptjs.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName || '',
        lastName: user.lastName || '',
        phone: user.phone || '',
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user (requires token)
app.get('/api/auth/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    let query = supabase.from('partico_users').select('*');
    query = decoded.id ? query.eq('id', decoded.id) : query.eq('email', decoded.email);
    const { data: user, error } = await query.single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { password, ...safeUser } = user;
    res.json({ user: safeUser });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Resend verification code
app.post('/api/auth/resend-code', rateLimit(5, 15 * 60 * 1000), async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    // Get existing verification request
    const { data: verifyRequest, error: queryError } = await supabase
      .from('partico_verification_requests')
      .select('*')
      .eq('email', email.toLowerCase())
      .eq('type', 'signup')
      .single();

    if (queryError || !verifyRequest) {
      return res.status(400).json({ error: 'No pending verification for this email' });
    }

    // Generate new verification code
    const code = generateVerificationCode();

    // Update verification request with new code
    const { error: updateError } = await supabase
      .from('partico_verification_requests')
      .update({
        code,
        expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      })
      .eq('email', email.toLowerCase())
      .eq('type', 'signup');

    if (updateError) {
      console.error('Verification update error:', updateError);
      return res.status(500).json({ error: 'Failed to resend code' });
    }

    // Send new verification email
    const emailHtml = `
      <div style="text-align: center; background: #0d0d0d; padding: 40px 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #fff;">
        <img src="https://res.cloudinary.com/dvrrwjm9f/image/upload/v1773603152/final_logo_myxdg2.png" alt="Partico" style="width: 100px; height: 100px; margin-bottom: 20px;">
        <h2 style="color: #00ff41; margin: 20px 0;">Your new verification code</h2>
        <p style="color: rgba(255,255,255,0.7); margin: 15px 0;">Your verification code is:</p>
        <h1 style="font-size: 48px; font-weight: bold; color: #00ff41; letter-spacing: 4px; margin: 30px 0;">${code}</h1>
        <p style="color: rgba(255,255,255,0.5); margin: 15px 0;">This code expires in 15 minutes.</p>
      </div>
    `;

    await sendEmail(email, 'Your new verification code', emailHtml);

    res.json({ message: 'Verification code resent', email });
  } catch (error) {
    console.error('Resend code error:', error);
    res.status(500).json({ error: 'Failed to resend code' });
  }
});

// ============================================================
// Social API: user search, friends, parties (requires tables:
// partico_friendships, partico_parties, partico_party_invites
// — see backend/supabase-social-schema.sql)
// ============================================================

function sanitizeUser(u) {
  if (!u) return null;
  const { password, ...safe } = u;
  return safe;
}

// Mask an email for display to other users, e.g. tob*****s11@ic***d.com
function maskEmail(email) {
  if (!email || !email.includes('@')) return '';
  const [local, domain] = email.split('@');
  const maskedLocal = local.length <= 4
    ? (local[0] || '') + '***'
    : local.slice(0, 3) + '*****' + local.slice(-3);
  const dot = domain.lastIndexOf('.');
  const name = dot > 0 ? domain.slice(0, dot) : domain;
  const tld = dot > 0 ? domain.slice(dot) : '';
  const maskedName = name.length <= 3 ? (name[0] || '') + '***' : name.slice(0, 2) + '***' + name.slice(-1);
  return maskedLocal + '@' + maskedName + tld;
}

// What other users are allowed to see about someone (no phone, no internals)
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    username: u.username,
    email: maskEmail(u.email),
    firstName: u.firstName || '',
    lastName: u.lastName || '',
    bio: u.bio || '',
  };
}

// Auth middleware: verifies JWT and loads the user row onto req.user
async function requireAuth(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, JWT_SECRET);
    let query = supabase.from('partico_users').select('*');
    query = decoded.id ? query.eq('id', decoded.id) : query.eq('email', decoded.email);
    const { data: user, error } = await query.single();
    if (error || !user) return res.status(401).json({ error: 'User not found' });
    req.user = sanitizeUser(user);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Search users by username, email, or name
app.get('/api/users/search', requireAuth, async (req, res) => {
  try {
    const raw = (req.query.q || '').toString().trim();
    if (!raw) return res.json({ users: [] });
    const q = raw.replace(/[^a-zA-Z0-9@._\s-]/g, '');
    if (!q) return res.json({ users: [] });

    let { data, error } = await supabase
      .from('partico_users')
      .select('*')
      .or(`username.ilike.*${q}*,email.ilike.*${q}*,firstName.ilike.*${q}*,lastName.ilike.*${q}*`)
      .neq('id', req.user.id)
      .limit(20);

    // Fallback if firstName/lastName columns don't exist yet
    if (error) {
      const retry = await supabase
        .from('partico_users')
        .select('*')
        .or(`username.ilike.*${q}*,email.ilike.*${q}*`)
        .neq('id', req.user.id)
        .limit(20);
      data = retry.data;
      error = retry.error;
    }

    if (error) {
      console.error('User search error:', error);
      return res.status(500).json({ error: 'Search failed' });
    }
    res.json({ users: (data || []).map(publicUser) });
  } catch (e) {
    console.error('Search error:', e);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Update own profile
app.put('/api/users/me', requireAuth, async (req, res) => {
  try {
    const allowed = ['firstName', 'lastName', 'phone', 'bio'];
    const updates = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) updates[k] = req.body[k];
    }
    if (Object.keys(updates).length === 0) return res.json({ user: req.user });
    const { error } = await supabase.from('partico_users').update(updates).eq('id', req.user.id);
    if (error) {
      console.error('Profile update error:', error);
      return res.status(500).json({ error: 'Profile update failed' });
    }
    res.json({ user: { ...req.user, ...updates } });
  } catch (e) {
    res.status(500).json({ error: 'Profile update failed' });
  }
});

function composeParty(row, inviteRows) {
  return {
    ...(row.data || {}),
    id: row.id,
    hostId: row.host_id,
    invites: (inviteRows || []).map((r) => ({ ...(r.data || {}), userId: r.user_id, status: r.status })),
  };
}

// Full account state: profile, friends, friend requests, parties
app.get('/api/state', requireAuth, async (req, res) => {
  try {
    const me = req.user;

    const { data: friendships, error: fErr } = await supabase
      .from('partico_friendships')
      .select('*')
      .or(`requester_id.eq.${me.id},addressee_id.eq.${me.id}`);
    if (fErr) {
      console.error('Friendships query error:', fErr);
      return res.status(500).json({ error: 'State load failed' });
    }

    const friends = [];
    const friendRequests = []; // incoming, pending
    const outgoingRequests = []; // sent by me, pending
    for (const f of friendships || []) {
      if (f.status === 'accepted') {
        friends.push(f.requester_id === me.id ? f.addressee_id : f.requester_id);
      } else if (f.addressee_id === me.id) {
        friendRequests.push({ from: f.requester_id, status: 'pending' });
      } else {
        outgoingRequests.push(f.addressee_id);
      }
    }

    const { data: myInvites } = await supabase
      .from('partico_party_invites')
      .select('party_id')
      .eq('user_id', me.id);
    const invitedPartyIds = [...new Set((myInvites || []).map((r) => r.party_id))];

    let partyQuery = supabase.from('partico_parties').select('*');
    if (invitedPartyIds.length > 0) {
      partyQuery = partyQuery.or(`host_id.eq.${me.id},id.in.(${invitedPartyIds.join(',')})`);
    } else {
      partyQuery = partyQuery.eq('host_id', me.id);
    }
    const { data: partyRows, error: pErr } = await partyQuery;
    if (pErr) {
      console.error('Parties query error:', pErr);
      return res.status(500).json({ error: 'State load failed' });
    }

    const partyIds = (partyRows || []).map((p) => p.id);
    let inviteRows = [];
    if (partyIds.length > 0) {
      const { data: ir } = await supabase
        .from('partico_party_invites')
        .select('*')
        .in('party_id', partyIds);
      inviteRows = ir || [];
    }

    const parties = (partyRows || []).map((row) =>
      composeParty(row, inviteRows.filter((r) => r.party_id === row.id))
    );

    // Collect every user id we need a profile for
    const profileIds = new Set([me.id, ...friends, ...outgoingRequests]);
    friendRequests.forEach((r) => profileIds.add(r.from));
    (partyRows || []).forEach((p) => profileIds.add(p.host_id));
    inviteRows.forEach((r) => profileIds.add(r.user_id));

    let profiles = [];
    if (profileIds.size > 0) {
      const { data: profRows } = await supabase
        .from('partico_users')
        .select('*')
        .in('id', [...profileIds]);
      profiles = (profRows || []).map((u) => u.id === me.id ? sanitizeUser(u) : publicUser(u));
    }

    res.json({
      user: me,
      friends,
      friendRequests,
      outgoingRequests,
      parties,
      profiles,
    });
  } catch (e) {
    console.error('State error:', e);
    res.status(500).json({ error: 'State load failed' });
  }
});

// Send a friend request (auto-accepts if they already requested you)
app.post('/api/friends/request', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const toUserId = (req.body.toUserId || '').toString();
    if (!toUserId || toUserId === me.id) return res.status(400).json({ error: 'Invalid user' });

    const { data: existing } = await supabase
      .from('partico_friendships')
      .select('*')
      .or(`and(requester_id.eq.${me.id},addressee_id.eq.${toUserId}),and(requester_id.eq.${toUserId},addressee_id.eq.${me.id})`);

    const row = (existing || [])[0];
    if (row) {
      if (row.status === 'pending' && row.requester_id === toUserId) {
        // They already asked us — accept
        await supabase.from('partico_friendships').update({ status: 'accepted' }).eq('id', row.id);
        return res.json({ success: true, status: 'accepted' });
      }
      return res.json({ success: true, status: row.status });
    }

    const { error } = await supabase
      .from('partico_friendships')
      .insert([{ requester_id: me.id, addressee_id: toUserId, status: 'pending' }]);
    if (error) {
      console.error('Friend request error:', error);
      return res.status(500).json({ error: 'Friend request failed' });
    }
    res.json({ success: true, status: 'pending' });
  } catch (e) {
    res.status(500).json({ error: 'Friend request failed' });
  }
});

// Accept or decline an incoming friend request
app.post('/api/friends/respond', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const { fromUserId, accept } = req.body;
    if (!fromUserId) return res.status(400).json({ error: 'fromUserId required' });

    if (accept) {
      const { error } = await supabase
        .from('partico_friendships')
        .update({ status: 'accepted' })
        .eq('requester_id', fromUserId)
        .eq('addressee_id', me.id);
      if (error) return res.status(500).json({ error: 'Failed to accept request' });
    } else {
      await supabase
        .from('partico_friendships')
        .delete()
        .eq('requester_id', fromUserId)
        .eq('addressee_id', me.id);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to respond to request' });
  }
});

// Remove a friend
app.post('/api/friends/remove', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const userId = (req.body.userId || '').toString();
    if (!userId) return res.status(400).json({ error: 'userId required' });
    await supabase
      .from('partico_friendships')
      .delete()
      .or(`and(requester_id.eq.${me.id},addressee_id.eq.${userId}),and(requester_id.eq.${userId},addressee_id.eq.${me.id})`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});

// Create or update a party. The host's client sends the whole party object.
app.post('/api/parties/sync', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const party = req.body.party;
    if (!party || !party.id) return res.status(400).json({ error: 'party with id required' });
    const partyId = party.id.toString();

    const { data: existing } = await supabase
      .from('partico_parties')
      .select('id, host_id')
      .eq('id', partyId)
      .maybeSingle();

    const isHost = !existing || existing.host_id === me.id;
    if (existing && !isHost) {
      // Guests may update shared content (photos, pops) but not invites/ownership
      const { data: myInvite } = await supabase
        .from('partico_party_invites')
        .select('id')
        .eq('party_id', partyId)
        .eq('user_id', me.id)
        .maybeSingle();
      if (!myInvite) return res.status(403).json({ error: 'Not allowed' });
    }

    const data = { ...party };
    delete data.id;
    delete data.hostId;
    delete data.invites;

    const hostId = existing ? existing.host_id : me.id;
    const { error: upsertErr } = await supabase
      .from('partico_parties')
      .upsert([{ id: partyId, host_id: hostId, data, updated_at: new Date().toISOString() }]);
    if (upsertErr) {
      console.error('Party upsert error:', upsertErr);
      return res.status(500).json({ error: 'Failed to save party' });
    }

    // Only the host's sync can add invitees or update host-controlled invite fields
    if (isHost && Array.isArray(party.invites) && party.invites.length > 0) {
      const { data: existingInvites } = await supabase
        .from('partico_party_invites')
        .select('*')
        .eq('party_id', partyId);
      const existingByUser = new Map((existingInvites || []).map((r) => [r.user_id, r]));

      const newRows = party.invites
        .filter((i) => i && i.userId && !existingByUser.has(i.userId))
        .map((i) => ({ party_id: partyId, user_id: i.userId, status: i.status || 'pending', data: i }));
      if (newRows.length > 0) {
        const { error: invErr } = await supabase.from('partico_party_invites').insert(newRows);
        if (invErr) console.error('Invite insert error:', invErr);
      }

      // Host-controlled fields (plus-one approval, nudges) merged without
      // touching the guest's own RSVP answers
      for (const i of party.invites) {
        if (!i || !i.userId) continue;
        const row = existingByUser.get(i.userId);
        if (!row) continue;
        const updates = {};
        if (i.plusOneApproved !== undefined && i.plusOneApproved !== (row.data || {}).plusOneApproved) {
          updates.plusOneApproved = i.plusOneApproved;
        }
        if (i.lastNudged !== undefined && i.lastNudged !== (row.data || {}).lastNudged) {
          updates.lastNudged = i.lastNudged;
        }
        if (Object.keys(updates).length > 0) {
          await supabase
            .from('partico_party_invites')
            .update({ data: { ...(row.data || {}), ...updates } })
            .eq('id', row.id);
        }
      }
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Party sync error:', e);
    res.status(500).json({ error: 'Failed to save party' });
  }
});

// Fetch one party (used when opening an invite link)
app.get('/api/parties/:id', requireAuth, async (req, res) => {
  try {
    const { data: row, error } = await supabase
      .from('partico_parties')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();
    if (error || !row) return res.status(404).json({ error: 'Party not found' });
    const { data: inviteRows } = await supabase
      .from('partico_party_invites')
      .select('*')
      .eq('party_id', row.id);
    const userIds = [row.host_id, ...(inviteRows || []).map((r) => r.user_id)];
    const { data: profRows } = await supabase
      .from('partico_users')
      .select('*')
      .in('id', [...new Set(userIds)]);
    res.json({ party: composeParty(row, inviteRows), users: (profRows || []).map(publicUser) });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load party' });
  }
});

// Join a party from an invite link (adds a pending invite for the caller)
app.post('/api/parties/:id/join', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const partyId = req.params.id;
    const { data: row } = await supabase
      .from('partico_parties')
      .select('*')
      .eq('id', partyId)
      .maybeSingle();
    if (!row) return res.status(404).json({ error: 'Party not found' });

    const { data: existing } = await supabase
      .from('partico_party_invites')
      .select('id')
      .eq('party_id', partyId)
      .eq('user_id', me.id)
      .maybeSingle();
    if (!existing) {
      const inviteObj = {
        userId: me.id, status: 'pending', dateVotes: [], drinkPref: '', dietary: '',
        answers: {}, plusOneRequested: false, plusOneApproved: false, plusOneName: '',
        questions: [], respondedAt: null,
      };
      const { error: insErr } = await supabase
        .from('partico_party_invites')
        .insert([{ party_id: partyId, user_id: me.id, status: 'pending', data: inviteObj }]);
      if (insErr) console.error('Join insert error:', insErr);
    }

    const { data: inviteRows } = await supabase
      .from('partico_party_invites')
      .select('*')
      .eq('party_id', partyId);
    const userIds = [row.host_id, ...(inviteRows || []).map((r) => r.user_id)];
    const { data: profRows } = await supabase
      .from('partico_users')
      .select('*')
      .in('id', [...new Set(userIds)]);
    res.json({ party: composeParty(row, inviteRows), users: (profRows || []).map(publicUser) });
  } catch (e) {
    console.error('Join error:', e);
    res.status(500).json({ error: 'Failed to join party' });
  }
});

// RSVP / update own invite response
app.post('/api/parties/:id/rsvp', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const partyId = req.params.id;
    const response = req.body.response || {};

    const { data: existing } = await supabase
      .from('partico_party_invites')
      .select('*')
      .eq('party_id', partyId)
      .eq('user_id', me.id)
      .maybeSingle();

    const merged = { ...((existing && existing.data) || {}), ...response, userId: me.id, respondedAt: Date.now() };
    const status = response.status || (existing && existing.status) || 'pending';

    const { error } = await supabase
      .from('partico_party_invites')
      .upsert([{ party_id: partyId, user_id: me.id, status, data: merged }], { onConflict: 'party_id,user_id' });
    if (error) {
      console.error('RSVP error:', error);
      return res.status(500).json({ error: 'Failed to save RSVP' });
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save RSVP' });
  }
});

// Delete a party (host only)
app.delete('/api/parties/:id', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const { data: row } = await supabase
      .from('partico_parties')
      .select('id, host_id')
      .eq('id', req.params.id)
      .maybeSingle();
    if (!row) return res.json({ success: true });
    if (row.host_id !== me.id) return res.status(403).json({ error: 'Only the host can delete a party' });
    await supabase.from('partico_party_invites').delete().eq('party_id', row.id);
    await supabase.from('partico_parties').delete().eq('id', row.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete party' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  let dbTest = null;
  if (supabase) {
    const { error } = await supabase.from('partico_users').select('id').limit(1);
    dbTest = error ? { code: error.code, message: error.message } : 'ok';
  }
  res.json({
    status: 'ok',
    nodeVersion: process.version,
    supabaseClientReady: !!supabase,
    supabaseInitError: supabaseInitError,
    dbTest,
    supabaseUrlPreview: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.substring(0, 40) : 'NOT SET',
    resendKeySet: !!process.env.RESEND_API_KEY,
    jwtSecretSet: !!process.env.JWT_SECRET,
  });
});

// Diagnostic endpoint - shows configuration status (safe for production)
app.get('/api/diag/config', (req, res) => {
  res.json({
    timestamp: new Date().toISOString(),
    nodeEnv: process.env.NODE_ENV,
    supabaseUrl: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.substring(0, 30) + '...' : 'NOT SET',
    supabaseUrlSet: !!process.env.SUPABASE_URL,
    supabaseKeySet: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
    jwtSecretSet: !!process.env.JWT_SECRET,
    resendApiKeySet: !!process.env.RESEND_API_KEY,
    port: process.env.PORT || 3001,
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
