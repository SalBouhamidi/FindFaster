import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import helmet from 'helmet';
import type { Express } from 'express';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import {
  SecurityMiddleware,
  CSRFProtectionMiddleware,
  RequestSanitizationMiddleware,
} from './common/middleware/security.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { rawBody: true });
  const configService = app.get(ConfigService);

  // Validate critical environment variables
  const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI', 'SESSION_SECRET'];
  const missingVars = requiredEnvVars.filter(
    (varName) => !process.env[varName],
  );

  if (missingVars.length > 0) {
    console.error(
      `❌ Missing required environment variables: ${missingVars.join(', ')}`,
    );
    process.exit(1);
  }

  // Security middleware - apply early
  app.use(compression()); // Compress responses

  // Helmet for additional security headers (but we'll use our custom one too)
  app.use(
    helmet({
      contentSecurityPolicy: false, // We handle this in our custom middleware
      crossOriginEmbedderPolicy: false,
    }),
  );

  // Custom security middleware
  app.use(new SecurityMiddleware().use.bind(new SecurityMiddleware()));
  app.use(
    new RequestSanitizationMiddleware().use.bind(
      new RequestSanitizationMiddleware(),
    ),
  );
  app.use(
    new CSRFProtectionMiddleware().use.bind(new CSRFProtectionMiddleware()),
  );

  // Enhanced CORS configuration
  const allowedOrigins = [
    configService.get<string>('app.frontendUrl'),
    process.env.ADMIN_URL,
    ...(process.env.ADDITIONAL_ALLOWED_ORIGINS?.split(',') || []),
  ].filter(Boolean);

  app.enableCors({
    origin: (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void,
    ) => {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);

      if (
        typeof origin === 'string' &&
        allowedOrigins.some(
          (allowed) =>
            typeof allowed === 'string' && origin.startsWith(allowed),
        )
      ) {
        return callback(null, true);
      }

      callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'X-CSRF-Token',
    ],
    exposedHeaders: [
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
    ],
    maxAge: 86400, // Cache preflight for 24 hours
  });

  // Enhanced global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      disableErrorMessages: process.env.NODE_ENV === 'production',
      validationError: {
        target: false,
        value: false,
      },
    }),
  );}


void bootstrap();
