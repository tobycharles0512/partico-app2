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
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
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
    const { email, firstName, lastName, phone, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Generate verification code
    const code = generateVerificationCode();

    // Store verification request
    const { error: verifyError } = await supabase
      .from('verification_requests')
      .insert([
        {
          email: email.toLowerCase(),
          code,
          firstName,
          lastName,
          phone,
          password, // Store hashed password after verify
          type: 'signup',
          expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(), // 15 min expiry
        },
      ]);

    if (verifyError) {
      console.error('Verification insert error:', verifyError);
      return res.status(500).json({ error: 'Failed to create verification request' });
    }

    // Send verification email
    const emailHtml = `
      <h2>Verify your Partico account</h2>
      <p>Your verification code is:</p>
      <h1 style="font-size: 32px; font-weight: bold; color: #00ff41;">${code}</h1>
      <p>This code expires in 15 minutes.</p>
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
    const { error: createError } = await supabase
      .from('users')
      .insert([
        {
          id: userId,
          email: email.toLowerCase(),
          password: hashedPassword,
          firstName: verifyRequest.firstName,
          lastName: verifyRequest.lastName,
          phone: verifyRequest.phone,
          createdAt: new Date().toISOString(),
        },
      ]);

    if (createError) {
      console.error('User creation error:', createError);
      return res.status(500).json({ error: 'Failed to create account' });
    }

    // Delete verification request
    await supabase
      .from('verification_requests')
      .delete()
      .eq('email', email.toLowerCase())
      .eq('code', code);

    // Generate JWT
    const token = jwt.sign(
      { userId, email: email.toLowerCase() },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: userId,
        email: email.toLowerCase(),
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

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Get user
    const { data: user, error: queryError } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (queryError || !user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare password
    const passwordMatch = await bcryptjs.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
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
      .select('id, email, firstName, lastName, phone, createdAt')
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

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
