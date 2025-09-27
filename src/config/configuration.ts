import 'dotenv/config';
import {
  validateEnvironment,
  logEnvironmentInfo,
} from '@config/environment.validator';

// Validate environment on module load (after .env is loaded)
const validatedEnv = validateEnvironment(process.env);

// Log environment info in development
if (validatedEnv.NODE_ENV === 'development') {
  logEnvironmentInfo(validatedEnv);
}

console.log('--- Debugging Google Config ---');
console.log('Validated GOOGLE_CLIENT_ID:', validatedEnv.GOOGLE_CLIENT_ID);
console.log('Validated GOOGLE_CLIENT_SECRET:', validatedEnv.GOOGLE_CLIENT_SECRET);
console.log('Validated GOOGLE_CALLBACK_URL:', validatedEnv.GOOGLE_CALLBACK_URL);
console.log('--- End Debug ---');

export default () => ({
  database: {
    uri: validatedEnv.MONGODB_URI,
  },
  google: {
    clientId: validatedEnv.GOOGLE_CLIENT_ID,
    clientSecret: validatedEnv.GOOGLE_CLIENT_SECRET,
    callbackURL:
      validatedEnv.GOOGLE_CALLBACK_URL ||
      `http://localhost:${validatedEnv.PORT}/api/auth/google/callback`,
  },
  jwt: {
    secret: validatedEnv.JWT_SECRET,
    expiresIn: validatedEnv.JWT_EXPIRES_IN,
  },
  app: {
    port: validatedEnv.PORT,
    nodeEnv: validatedEnv.NODE_ENV,
    frontendUrl:
      validatedEnv.FRONTEND_URL || `http://localhost:${validatedEnv.PORT}`,
    adminUrl: validatedEnv.ADMIN_URL,
    trustProxy: validatedEnv.TRUST_PROXY,
    enableApiDocs: validatedEnv.ENABLE_API_DOCS,
  },
  session: {
    secret: validatedEnv.SESSION_SECRET,
  },
  email: {
    host: validatedEnv.EMAIL_HOST,
    port: validatedEnv.EMAIL_PORT,
    user: validatedEnv.EMAIL_USER,
    pass: validatedEnv.EMAIL_PASS,
    from: validatedEnv.EMAIL_FROM,
  },
  security: {
    allowedOrigins:
      validatedEnv.ADDITIONAL_ALLOWED_ORIGINS?.split(',').filter(Boolean) || [],
    logLevel: validatedEnv.LOG_LEVEL,
  },
});
