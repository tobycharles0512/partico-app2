const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const WebSocket = require('ws');
const cors = require('cors');
const { validateMessageText, buildMessage, appendMessage } = require('./messages');
const { buildStatePartyOr } = require('./parties');
const { followAction, deriveRelationships } = require('./follows');
const { selectDiscoverable, relationshipTo } = require('./discover');
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
        <img src="https://partico.app/partico-logo.png" alt="Partico" style="width: 100px; height: 100px; margin-bottom: 20px;">
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
    const { email, code, acceptedTerms } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    // Accounts can only be created after accepting the Terms & Conditions
    if (!acceptedTerms) {
      return res.status(400).json({ error: 'You must accept the Terms & Conditions to create an account' });
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
    newUserRow.accepted_terms_at = new Date().toISOString();

    let insertResponse = await supabase
      .from('partico_users')
      .insert([newUserRow]);

    // If the accepted_terms_at column hasn't been added in Supabase yet,
    // retry without it so signups never break
    if (insertResponse.error && String(insertResponse.error.message || '').includes('accepted_terms_at')) {
      delete newUserRow.accepted_terms_at;
      insertResponse = await supabase.from('partico_users').insert([newUserRow]);
    }

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
        <img src="https://partico.app/partico-logo.png" alt="Partico" style="width: 100px; height: 100px; margin-bottom: 20px;">
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
    profilePic: u.profilePic || null,
    is_public: u.is_public === true,
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
    const allowed = ['firstName', 'lastName', 'phone', 'bio', 'profilePic', 'is_public'];
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

    const { data: followRows, error: fErr } = await supabase
      .from('partico_follows')
      .select('follower_id, followee_id, status')
      .or(`follower_id.eq.${me.id},followee_id.eq.${me.id}`);
    if (fErr) {
      console.error('Follows query error:', fErr);
      return res.status(500).json({ error: 'State load failed' });
    }
    const rel = deriveRelationships(me.id, followRows || []);
    const friends = rel.friends;
    const friendRequests = rel.incomingRequests.map((from) => ({ from, status: 'pending' }));
    const outgoingRequests = rel.outgoingRequests;
    const following = rel.following;
    const followers = rel.followers;

    const { data: myInvites } = await supabase
      .from('partico_party_invites')
      .select('party_id')
      .eq('user_id', me.id);
    const invitedPartyIds = [...new Set((myInvites || []).map((r) => r.party_id))];

    // Load the user's own parties, parties they're invited to, AND every public
    // party — so a brand-new account can discover public events hosted by others.
    const { data: partyRows, error: pErr } = await supabase
      .from('partico_parties')
      .select('*')
      .or(buildStatePartyOr(me.id, invitedPartyIds));
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
    const profileIds = new Set([me.id, ...friends, ...outgoingRequests, ...following, ...followers]);
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
      user: { ...me, friends, following, followers, outgoingRequests },
      friends,
      following,
      followers,
      friendRequests,
      outgoingRequests,
      incomingRequests: rel.incomingRequests,
      parties,
      profiles,
    });
  } catch (e) {
    console.error('State error:', e);
    res.status(500).json({ error: 'State load failed' });
  }
});

// ── Shared follow helpers (single source of truth used by both new and legacy routes) ──

async function doFollow(meId, targetId) {
  const { data: target } = await supabase
    .from('partico_users').select('id, is_public').eq('id', targetId).maybeSingle();
  if (!target) return { notFound: true };

  const { data: reverse } = await supabase
    .from('partico_follows').select('status')
    .eq('follower_id', targetId).eq('followee_id', meId).maybeSingle();

  const { data: forwardRow } = await supabase
    .from('partico_follows').select('status')
    .eq('follower_id', meId).eq('followee_id', targetId).maybeSingle();

  let { forward, activateReverse } = followAction({
    targetIsPublic: target.is_public === true,
    reverseStatus: reverse ? reverse.status : null,
  });
  if (forwardRow && forwardRow.status === 'active') forward = 'active'; // never downgrade an established follow

  const { error: upErr } = await supabase
    .from('partico_follows')
    .upsert({ follower_id: meId, followee_id: targetId, status: forward },
      { onConflict: 'follower_id,followee_id' });
  if (upErr) { console.error('Follow upsert error:', upErr); return { dbError: true }; }

  if (activateReverse) {
    await supabase.from('partico_follows')
      .update({ status: 'active' })
      .eq('follower_id', targetId).eq('followee_id', meId);
  }
  return { status: activateReverse ? 'friend' : forward };
}

async function doRespond(meId, fromUserId, accept) {
  if (accept) {
    const { data: updated, error: e1 } = await supabase.from('partico_follows')
      .update({ status: 'active' })
      .eq('follower_id', fromUserId).eq('followee_id', meId).select();
    if (e1) { console.error('Accept request error:', e1); return { dbError: true }; }
    if (!updated || updated.length === 0) return { success: true, status: 'none' }; // no pending request to accept
    const { error: e2 } = await supabase.from('partico_follows')
      .upsert({ follower_id: meId, followee_id: fromUserId, status: 'active' },
        { onConflict: 'follower_id,followee_id' });
    if (e2) { console.error('Accept upsert error:', e2); return { dbError: true }; }
  } else {
    const { error: delErr } = await supabase.from('partico_follows').delete()
      .eq('follower_id', fromUserId).eq('followee_id', meId);
    if (delErr) { console.error('Decline request error:', delErr); return { dbError: true }; }
  }
  return { success: true };
}

async function doUnfollow(meId, targetId) {
  const { error: delErr } = await supabase.from('partico_follows').delete()
    .eq('follower_id', meId).eq('followee_id', targetId);
  if (delErr) { console.error('Unfollow error:', delErr); return { dbError: true }; }
  return { success: true };
}

// ── Legacy friends routes (compatibility aliases over the follow graph) ──

// Send a friend request (auto-accepts if they already requested you)
app.post('/api/friends/request', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const toUserId = (req.body.toUserId || '').toString();
    if (!toUserId || toUserId === me.id) return res.status(400).json({ error: 'Invalid user' });
    const result = await doFollow(me.id, toUserId);
    if (result.notFound) return res.status(404).json({ error: 'User not found' });
    if (result.dbError) return res.status(500).json({ error: 'Friend request failed' });
    res.json({ success: true, status: result.status });
  } catch (e) {
    console.error('Friend request error:', e);
    res.status(500).json({ error: 'Friend request failed' });
  }
});

// Accept or decline an incoming friend request
app.post('/api/friends/respond', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const { fromUserId, accept } = req.body;
    if (!fromUserId) return res.status(400).json({ error: 'fromUserId required' });
    const result = await doRespond(me.id, fromUserId.toString(), accept === true);
    if (result.dbError) return res.status(500).json({ error: 'Failed to respond to request' });
    res.json({ success: true });
  } catch (e) {
    console.error('Friends respond error:', e);
    res.status(500).json({ error: 'Failed to respond to request' });
  }
});

// Remove a friend: one-directional unfollow (deletes caller's outbound edge only;
// the reverse edge survives until the other user unfollows — Instagram-style).
app.post('/api/friends/remove', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const userId = (req.body.userId || '').toString();
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const result = await doUnfollow(me.id, userId);
    if (result.dbError) return res.status(500).json({ error: 'Failed to remove friend' });
    res.json({ success: true });
  } catch (e) {
    console.error('Friends remove error:', e);
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});

// ── New follow endpoints ──

// Follow a user. Public target -> active immediately. Private target ->
// pending (a friend request). If the target already follows/requested us,
// following back makes us friends (both edges active). Replaces friends/request.
app.post('/api/follow', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const targetId = (req.body.targetId || req.body.toUserId || '').toString();
    if (!targetId || targetId === me.id) return res.status(400).json({ error: 'Invalid user' });
    const result = await doFollow(me.id, targetId);
    if (result.notFound) return res.status(404).json({ error: 'User not found' });
    if (result.dbError) return res.status(500).json({ error: 'Follow failed' });
    res.json({ success: true, status: result.status });
  } catch (e) {
    console.error('Follow error:', e);
    res.status(500).json({ error: 'Follow failed' });
  }
});

// Approve or decline an incoming follow request. Approving creates the mutual
// active pair (instant friends). Declining deletes the pending edge.
app.post('/api/follow/respond', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const fromUserId = (req.body.fromUserId || '').toString();
    const accept = req.body.accept === true;
    if (!fromUserId) return res.status(400).json({ error: 'fromUserId required' });
    const result = await doRespond(me.id, fromUserId, accept);
    if (result.dbError) return res.status(500).json({ error: 'Failed to respond to request' });
    res.json({ success: true });
  } catch (e) {
    console.error('Follow respond error:', e);
    res.status(500).json({ error: 'Failed to respond to request' });
  }
});

// Unfollow: delete only my outbound edge. The reverse edge survives
// (Instagram-style). Replaces friends/remove.
app.post('/api/unfollow', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const targetId = (req.body.targetId || req.body.userId || '').toString();
    if (!targetId) return res.status(400).json({ error: 'targetId required' });
    const result = await doUnfollow(me.id, targetId);
    if (result.dbError) return res.status(500).json({ error: 'Unfollow failed' });
    res.json({ success: true });
  } catch (e) {
    console.error('Unfollow error:', e);
    res.status(500).json({ error: 'Unfollow failed' });
  }
});

// Discover feed: public events the requester may see, with audience rules
// (everyone / mutual / friends) enforced server-side and viewerRelationship
// attached so the client can bucket the For You / Following / Friends tabs.
app.get('/api/discover', requireAuth, async (req, res) => {
  try {
    const me = req.user;

    const { data: myFollowRows, error: fErr } = await supabase
      .from('partico_follows')
      .select('follower_id, followee_id, status')
      .or(`follower_id.eq.${me.id},followee_id.eq.${me.id}`);
    if (fErr) {
      console.error('Discover follows error:', fErr);
      return res.status(500).json({ error: 'Discover failed' });
    }
    const myFriendIds = deriveRelationships(me.id, myFollowRows || []).friends;

    const { data: allRows, error: pErr } = await supabase
      .from('partico_parties')
      .select('id, host_id, data');
    if (pErr) {
      console.error('Discover parties error:', pErr);
      return res.status(500).json({ error: 'Discover failed' });
    }
    const publicRows = (allRows || []).filter(
      (r) => r.data && r.data.isPrivate === false && r.host_id !== me.id);

    const hostIds = [...new Set(publicRows.map((r) => r.host_id))];
    const hostFriendsById = {};
    if (hostIds.length > 0) {
      const { data: hostRows, error: hfErr } = await supabase
        .from('partico_follows')
        .select('follower_id, followee_id, status')
        .eq('status', 'active')
        .or(`follower_id.in.(${hostIds.join(',')}),followee_id.in.(${hostIds.join(',')})`);
      if (hfErr) {
        console.error('Discover host-follows error:', hfErr);
        return res.status(500).json({ error: 'Discover failed' });
      }
      for (const hostId of hostIds) {
        hostFriendsById[hostId] = deriveRelationships(hostId, hostRows || []).friends;
      }
    }

    const candidates = publicRows.map((r) => ({
      id: r.id,
      hostId: r.host_id,
      isPrivate: false,
      audience: (r.data && r.data.audience) || 'everyone',
    }));
    const eligibleIds = new Set(
      selectDiscoverable({
        parties: candidates,
        viewerId: me.id,
        viewerFriendIds: myFriendIds,
        hostFriendsById,
      }).map((p) => p.id));
    const eligibleRows = publicRows.filter((r) => eligibleIds.has(r.id));

    const partyIds = eligibleRows.map((r) => r.id);
    let inviteRows = [];
    if (partyIds.length > 0) {
      const { data: ir } = await supabase
        .from('partico_party_invites')
        .select('party_id, user_id, status')
        .in('party_id', partyIds);
      inviteRows = ir || [];
    }
    const parties = eligibleRows.map((row) => {
      const composed = composeParty(row, inviteRows.filter((r) => r.party_id === row.id));
      composed.viewerRelationship = relationshipTo(
        me.id, row.host_id, myFriendIds, hostFriendsById[row.host_id] || []);
      return composed;
    });

    const profileIds = [...new Set(eligibleRows.map((r) => r.host_id))];
    let profiles = [];
    if (profileIds.length > 0) {
      const { data: profRows } = await supabase
        .from('partico_users')
        .select('*')
        .in('id', profileIds);
      profiles = (profRows || []).map(publicUser);
    }

    res.json({ parties, profiles });
  } catch (e) {
    console.error('Discover error:', e);
    res.status(500).json({ error: 'Discover failed' });
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

// Record that someone opened the invite. Counting happens server-side so the
// host sees views from ALL guests (the client can't sum across devices, and a
// guest syncing the whole party blob would clobber host-owned fields). The
// host's own opens don't count, so the number reflects real reach.
// Read-modify-write isn't perfectly atomic, but it's the single source of truth
// and matches the rest of this codebase's blob-update pattern.
app.post('/api/parties/:id/view', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const partyId = req.params.id;

    const { data: row, error } = await supabase
      .from('partico_parties')
      .select('host_id, data')
      .eq('id', partyId)
      .maybeSingle();
    if (error || !row) return res.status(404).json({ error: 'Party not found' });

    const current = (row.data && row.data.inviteViews) || 0;
    // Don't let the host inflate their own analytics by opening the invite.
    if (row.host_id === me.id) return res.json({ success: true, inviteViews: current });

    const inviteViews = current + 1;
    const { error: updErr } = await supabase
      .from('partico_parties')
      .update({ data: { ...(row.data || {}), inviteViews }, updated_at: new Date().toISOString() })
      .eq('id', partyId);
    if (updErr) {
      console.error('Invite view update error:', updErr);
      return res.status(500).json({ error: 'Failed to record view' });
    }
    res.json({ success: true, inviteViews });
  } catch (e) {
    res.status(500).json({ error: 'Failed to record view' });
  }
});

// Host<->guest 1-to-1 chat. Either the host or the guest themselves may post.
// The message is appended to the guest's invite row (server-side append = race-safe).
// The recipient's 'message' notif is delivered client-side via the existing
// notifs/saveUsers path (same as nudges), since notifs are not a DB column.
app.post('/api/parties/:id/message', requireAuth, async (req, res) => {
  try {
    const me = req.user;
    const partyId = req.params.id;
    const { guestId, text } = req.body || {};

    if (!guestId) return res.status(400).json({ error: 'guestId required' });
    if (!validateMessageText(text)) return res.status(400).json({ error: 'Message text required' });

    // Look up the party to find the host.
    const { data: party } = await supabase
      .from('partico_parties')
      .select('id, host_id')
      .eq('id', partyId)
      .maybeSingle();
    if (!party) return res.status(404).json({ error: 'Party not found' });

    const isHost = party.host_id === me.id;
    const isGuest = me.id === guestId;
    if (!isHost && !isGuest) return res.status(403).json({ error: 'Not allowed' });

    // Load the guest's invite row (the thread lives here).
    const { data: invite } = await supabase
      .from('partico_party_invites')
      .select('*')
      .eq('party_id', partyId)
      .eq('user_id', guestId)
      .maybeSingle();
    if (!invite) return res.status(404).json({ error: 'No invite for this guest' });

    const msg = buildMessage({ from: me.id, text });
    const nextData = { ...(invite.data || {}), thread: appendMessage((invite.data || {}).thread, msg) };

    const { error: updErr } = await supabase
      .from('partico_party_invites')
      .update({ data: nextData })
      .eq('id', invite.id);
    if (updErr) {
      console.error('Message append error:', updErr);
      return res.status(500).json({ error: 'Failed to send message' });
    }

    res.json({ success: true, message: msg });
  } catch (e) {
    console.error('Send message error:', e);
    res.status(500).json({ error: 'Failed to send message' });
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
// Only start the HTTP listener when run directly (node server.js). When required
// by a test, export the app + a Supabase injector so endpoints can be exercised
// against a stub without a real DB.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = { app, __setSupabase: (client) => { supabase = client; } };
