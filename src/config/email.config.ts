import { registerAs } from '@nestjs/config';

export default registerAs('email', () => ({
  // SMTP Configuration
  smtp: {
    host: process.env.EMAIL_SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_SMTP_PORT || '587', 10),
    secure: process.env.EMAIL_SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_SMTP_USER,
      pass: process.env.EMAIL_SMTP_PASS,
    },
  },

  // Email Templates Configuration
  templates: {
    baseUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
    from: {
      name: process.env.EMAIL_FROM_NAME || 'Find Faster',
      address: process.env.EMAIL_FROM_ADDRESS || 'bouhamidi.sal@gmail.com',
    },
    support: {
      name: 'FindFaster Support',
      address: process.env.EMAIL_SUPPORT_ADDRESS || 'bouhamidi.sal@gmail.com',
    },
  },

  // Email Verification Settings
  verification: {
    expiresIn:
      parseInt(process.env.EMAIL_VERIFICATION_EXPIRES_IN || '24', 10) *
      60 *
      60 *
      1000, // 24 hours in milliseconds
    maxAttempts: parseInt(
      process.env.EMAIL_VERIFICATION_MAX_ATTEMPTS || '3',
      10,
    ),
  },

  // Password Reset Settings
  passwordReset: {
    expiresIn:
      parseInt(process.env.PASSWORD_RESET_EXPIRES_IN || '1', 10) *
      60 *
      60 *
      1000, // 1 hour in milliseconds
    maxAttempts: parseInt(process.env.PASSWORD_RESET_MAX_ATTEMPTS || '3', 10),
  },

  // Rate Limiting
  rateLimiting: {
    enabled: process.env.EMAIL_RATE_LIMITING_ENABLED !== 'false',
    maxEmailsPerHour: parseInt(process.env.EMAIL_MAX_PER_HOUR || '10', 10),
    maxEmailsPerDay: parseInt(process.env.EMAIL_MAX_PER_DAY || '50', 10),
  },
}));
