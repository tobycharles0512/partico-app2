const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

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
      { auth: { persistSession: false, autoRefreshToken: false } }
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
app.post('/api/auth/signup', async (req, res) => {
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
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    console.log('Email check result:', { existingEmail: !!existingEmail, errorCode: emailCheckError?.code, errorMessage: emailCheckError?.message });

    if (emailCheckError && emailCheckError.code !== 'PGRST116') {
      console.error('Email check error (code !== PGRST116):', emailCheckError);
      return res.status(500).json({ error: 'Database error' });
    }

    if (existingEmail) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if username already exists
    console.log('Checking if username already exists:', username.toLowerCase());
    const { data: existingUsername, error: usernameCheckError } = await supabase
      .from('users')
      .select('id')
      .eq('username', username.toLowerCase())
      .single();

    console.log('Username check result:', { existingUsername: !!existingUsername, errorCode: usernameCheckError?.code, errorMessage: usernameCheckError?.message });

    if (usernameCheckError && usernameCheckError.code !== 'PGRST116') {
      console.error('Username check error (code !== PGRST116):', usernameCheckError);
      return res.status(500).json({ error: 'Database error' });
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
      .from('verification_requests')
      .delete()
      .eq('email', email.toLowerCase());

    if (deleteError) {
      console.error('Error deleting old requests:', deleteError);
    } else {
      console.log('Successfully deleted old requests');
    }

    // Store verification request
    const verificationData = {
      email: email.toLowerCase(),
      username: username.toLowerCase(),
      code,
      password,
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
      .from('verification_requests')
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
app.post('/api/auth/verify-signup', async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code required' });
    }

    // Get verification request
    const { data: verifyRequest, error: queryError } = await supabase
      .from('verification_requests')
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

    // Hash password
    const hashedPassword = await bcryptjs.hash(verifyRequest.password, 10);

    // Create user
    const userId = Math.random().toString(36).substring(7); // Generate simple ID
    console.log('Attempting to create user:', { userId, email: email.toLowerCase(), username: verifyRequest.username, timestamp: new Date().toISOString() });

    const insertResponse = await supabase
      .from('users')
      .insert([
        {
          id: userId,
          email: email.toLowerCase(),
          username: verifyRequest.username,
          password: hashedPassword,
        },
      ]);

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
      .from('users')
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
      .from('verification_requests')
      .delete()
      .eq('email', email.toLowerCase())
      .eq('code', code);

    // Generate JWT
    const token = jwt.sign(
      { email: email.toLowerCase(), username: verifyRequest.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        email: email.toLowerCase(),
        username: verifyRequest.username,
      },
    });
  } catch (error) {
    console.error('Verify signup error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Login (with username or email)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername || !password) {
      return res.status(400).json({ error: 'Email/username and password required' });
    }

    // Try to find user by email or username
    const normalizedInput = emailOrUsername.toLowerCase();

    const { data: user, error: queryError } = await supabase
      .from('users')
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
      { email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        email: user.email,
        username: user.username,
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

    const { data: user, error } = await supabase
      .from('users')
      .select('email, username')
      .eq('email', decoded.email)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Resend verification code
app.post('/api/auth/resend-code', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    // Get existing verification request
    const { data: verifyRequest, error: queryError } = await supabase
      .from('verification_requests')
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
      .from('verification_requests')
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

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    supabaseClientReady: !!supabase,
    supabaseInitError: supabaseInitError,
    supabaseUrlSet: !!process.env.SUPABASE_URL,
    supabaseUrlPreview: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.substring(0, 40) : 'NOT SET',
    supabaseKeySet: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
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
