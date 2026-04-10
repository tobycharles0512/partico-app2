// Polyfill for Node.js environments without fetch
if (!globalThis.fetch) {
  const fetch = require('node-fetch');
  globalThis.fetch = fetch;
  globalThis.Headers = fetch.Headers;
  globalThis.Request = fetch.Request;
  globalThis.Response = fetch.Response;
}

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
const supabase = createClient(
  process.env.SUPABASE_URL || 'https://placeholder.supabase.co',
  process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder-key'
);

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const RESEND_API_KEY = process.env.RESEND_API_KEY;

// Helper: Generate 6-digit verification code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper: Send email via Resend
async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) {
    console.log(`[Mock Email] To: ${to}, Subject: ${subject}`);
    return true;
  }

  try {
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

    return response.ok;
  } catch (error) {
    console.error('Email send error:', error);
    return false;
  }
}

// Signup: Send verification email
app.post('/api/auth/signup', async (req, res) => {
  try {
    console.log('=== SIGNUP REQUEST ===');
    console.log('Body:', JSON.stringify(req.body));
    const { email, username, firstName, lastName, phone, password } = req.body;

    if (!email || !password || !username) {
      return res.status(400).json({ error: 'Email, username, and password required' });
    }

    // Check if email already exists
    const { data: existingEmail } = await supabase
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    if (existingEmail) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check if username already exists
    const { data: existingUsername } = await supabase
      .from('users')
      .select('id')
      .eq('username', username.toLowerCase())
      .single();

    if (existingUsername) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Generate verification code
    const code = generateVerificationCode();

    // Delete any existing verification requests for this email (to allow resend)
    await supabase
      .from('verification_requests')
      .delete()
      .eq('email', email.toLowerCase());

    // Store verification request
    const insertData = {
      email: email.toLowerCase(),
      username: username.toLowerCase(),
      code,
      firstName: firstName || null,
      lastName: lastName || null,
      phone: phone || null,
      password,
      type: 'signup',
      expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(), // 15 min expiry
    };
    console.log('Inserting verification request:', JSON.stringify(insertData));

    const { error: verifyError } = await supabase
      .from('verification_requests')
      .insert([insertData]);

    if (verifyError) {
      console.error('Verification insert error:', JSON.stringify(verifyError, null, 2));
      return res.status(400).json({
        error: 'Verification request failed',
        details: verifyError.message || 'Unknown error',
        code: verifyError.code || 'UNKNOWN'
      });
    }

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

    await sendEmail(email, 'Verify your Partico account', emailHtml);

    res.json({ message: 'Verification email sent', email });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed' });
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
    const userId = Math.random().toString(36).substring(7); // Simple ID generation
    console.log('Attempting to create user with:', { userId, email: email.toLowerCase(), username: verifyRequest.username });

    const { error: createError } = await supabase
      .from('users')
      .insert([
        {
          id: userId,
          email: email.toLowerCase(),
          username: verifyRequest.username,
          password: hashedPassword,
        },
      ]);

    if (createError) {
      console.error('=== USER CREATION FAILED ===');
      console.error('Error code:', createError.code);
      console.error('Error message:', createError.message);
      console.error('Error details:', createError.details);
      console.error('Full error:', JSON.stringify(createError, null, 2));
      return res.status(500).json({ error: 'Failed to create account', details: createError.message });
    }

    console.log('User created successfully with userId:', userId);

    // Delete verification request
    await supabase
      .from('verification_requests')
      .delete()
      .eq('email', email.toLowerCase())
      .eq('code', code);

    // Generate JWT
    const token = jwt.sign(
      { userId, email: email.toLowerCase(), username: verifyRequest.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: userId,
        email: email.toLowerCase(),
        username: verifyRequest.username,
        firstName: verifyRequest.firstName,
        lastName: verifyRequest.lastName,
        phone: verifyRequest.phone,
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

    console.log('=== LOGIN ATTEMPT ===');
    console.log('Input:', normalizedInput);

    const { data: users, error: queryError } = await supabase
      .from('users')
      .select('id, email, username, password')
      .or(`email.eq.${normalizedInput},username.eq.${normalizedInput}`);

    console.log('Query result - Users found:', users?.length, 'Error:', queryError);

    if (queryError) {
      console.error('=== USER QUERY ERROR ===');
      console.error('Error:', JSON.stringify(queryError, null, 2));
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    const user = users && users.length > 0 ? users[0] : null;

    if (!user) {
      console.error('=== USER NOT FOUND ===');
      console.error('Searched for email or username:', normalizedInput);
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    // Compare password
    console.log('User found. Comparing password...');
    console.log('User password hash exists:', !!user.password);

    const passwordMatch = await bcryptjs.compare(password, user.password);

    console.log('Password match result:', passwordMatch);
    if (!passwordMatch) {
      console.error('=== PASSWORD MISMATCH ===');
      console.error('Email/Username:', normalizedInput);
      console.error('User ID:', user.id);
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }

    console.log('Password verified successfully');

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
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
      .select('id, email, username, firstName, lastName, phone, createdAt')
      .eq('id', decoded.userId)
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

// Diagnostic endpoint - check if a user exists in Supabase
app.get('/api/diag/user/:emailOrUsername', async (req, res) => {
  try {
    const input = req.params.emailOrUsername.toLowerCase();
    console.log('=== DIAGNOSTIC: Checking for user:', input);

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, username, password')
      .or(`email.eq.${input},username.eq.${input}`)
      .single();

    if (error) {
      console.error('Query error:', error);
      return res.json({
        found: false,
        error: error.message,
        code: error.code
      });
    }

    if (!user) {
      console.error('User not found');
      return res.json({
        found: false,
        message: 'User not found in database'
      });
    }

    console.log('User found:', { id: user.id, email: user.email, username: user.username, hasPassword: !!user.password });
    res.json({
      found: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        hasPassword: !!user.password
      }
    });
  } catch (error) {
    console.error('Diagnostic error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
// Force redeploy Sun 22 Mar 2026 14:00:03 GMT
