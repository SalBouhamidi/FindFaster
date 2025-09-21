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
  const app = await NestFactory.create(AppModule);
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
  );

  // Enhanced session configuration
  const sessionSecret =
    configService.get<string>('session.secret') ?? 'fallback-session-secret';
  if (
    sessionSecret === 'fallback-session-secret' &&
    process.env.NODE_ENV === 'production'
  ) {
    console.error(
      '❌ Production environment detected with fallback session secret!',
    );
    process.exit(1);
  }

  app.use(
    session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: false,
      name: 'findfaster.session',
      cookie: {
        secure: configService.get<string>('app.nodeEnv') === 'production',
        httpOnly: true,
        maxAge: 2 * 60 * 60 * 1000, // 2 hours (shorter for security)
        sameSite: 'lax',
      },
      rolling: true, // Reset expiry on each request
      // Persistent session store (MongoDB)
      store: MongoStore.create({
        mongoUrl: configService.get<string>('database.uri')!,
        dbName: 'findfaster',
        collectionName: 'sessions',
        ttl: 2 * 60 * 60, // 2 hours in seconds
        autoRemove: 'native',
        touchAfter: 300, // reduce write frequency
      }),
    }),
  );

  // Cookie parser middleware
  app.use(cookieParser(configService.get<string>('session.secret')));

  // Global route prefix
  app.setGlobalPrefix('api', {
    exclude: ['/health', '/metrics'], // Health check endpoints
  });

  // API Docs (Swagger) - enabled in development or when explicitly toggled
  const enableApiDocs =
    configService.get<boolean>('app.enableApiDocs') === true ||
    configService.get<string>('app.nodeEnv') !== 'production';
  if (enableApiDocs) {
    const swaggerConfig = new DocumentBuilder()
      .setTitle('Dork Engine')
      .setDescription('API documentation for Dork Engine Backend')
      .setVersion('1.0.0')
      .addBearerAuth(
        { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        'JWT-auth',
      )
      .build();
    const document = SwaggerModule.createDocument(app, swaggerConfig);
    SwaggerModule.setup('docs', app, document, { useGlobalPrefix: true });
  }

  // Trust proxy if behind reverse proxy
  if (process.env.TRUST_PROXY === 'true') {
    app.enableCors({ credentials: true });
    await app.init();
    const expressInstance = app
      .getHttpAdapter()
      .getInstance() as unknown as Express;
    expressInstance.set('trust proxy', 1);
  }

  const port = configService.get<number>('app.port') || 3000;
  await app.listen(port, '0.0.0.0');

  console.log(`🚀 DorkEngine Backend running on port ${port}`);
  console.log(`📄 Environment: ${configService.get<string>('app.nodeEnv')}`);
  console.log(
    `🌐 Frontend URL: ${configService.get<string>('app.frontendUrl')}`,
  );
  console.log(`🔒 Security middleware enabled`);
  console.log(`🛡️  CORS configured for ${allowedOrigins.length} origins`);
}

void bootstrap();
