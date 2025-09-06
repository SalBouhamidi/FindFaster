import { plainToClass, Transform } from 'class-transformer';
import {
  IsString,
  IsNumber,
  IsOptional,
  IsUrl,
  validateSync,
  IsBoolean,
} from 'class-validator';

function transformBlankToUndefined({ value }: { value: unknown }) {
  if (typeof value === 'string' && value.trim() === '') {
    return undefined;
  }
  return value;
}

export class EnvironmentVariables {
  @IsString()
  NODE_ENV: string = 'development';

  @IsNumber()
  @Transform(({ value }) => {
    const parsed = parseInt(value as string, 10);
    return isNaN(parsed) ? 3000 : parsed;
  })
  PORT: number = 3000;

  @IsString()
  MONGODB_URI: string;

  @IsString()
  JWT_SECRET: string;

  @IsString()
  @IsOptional()
  JWT_EXPIRES_IN?: string = '15m';

  @IsString()
  SESSION_SECRET: string;

  @IsString()
  @IsOptional()
  GOOGLE_CLIENT_ID?: string;

  @IsString()
  @IsOptional()
  GOOGLE_CLIENT_SECRET?: string;

  @Transform(transformBlankToUndefined)
  @IsUrl({ require_tld: false })
  @IsOptional()
  GOOGLE_CALLBACK_URL?: string;

  @Transform(transformBlankToUndefined)
  @IsUrl({ require_tld: false })
  @IsOptional()
  FRONTEND_URL?: string = 'http://localhost:5173';

  @Transform(transformBlankToUndefined)
  @IsUrl({ require_tld: false })
  @IsOptional()
  ADMIN_URL?: string;

  @IsString()
  @IsOptional()
  EMAIL_HOST?: string;

  @IsNumber()
  @IsOptional()
  @Transform(({ value }) => {
    if (!value) return undefined;
    const parsed = parseInt(value as string, 10);
    return isNaN(parsed) ? undefined : parsed;
  })
  EMAIL_PORT?: number;

  @IsString()
  @IsOptional()
  EMAIL_USER?: string;

  @IsString()
  @IsOptional()
  EMAIL_PASS?: string;

  @IsString()
  @IsOptional()
  EMAIL_FROM?: string;

  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => value === 'true')
  TRUST_PROXY?: boolean = false;

  @IsString()
  @IsOptional()
  ADDITIONAL_ALLOWED_ORIGINS?: string;

  @IsString()
  @IsOptional()
  LOG_LEVEL?: string = 'info';

  @IsBoolean()
  @IsOptional()
  @Transform(({ value }) => value === 'true')
  ENABLE_API_DOCS?: boolean = false;
}

export function validateEnvironment(config: Record<string, unknown>) {
  const validatedConfig = plainToClass(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    const errorMessages = errors
      .map((error) => Object.values(error.constraints || {}).join(', '))
      .join('; ');

    throw new Error(`Environment validation failed: ${errorMessages}`);
  }

  // Additional custom validations
  validateSecurityRequirements(validatedConfig);

  return validatedConfig;
}

function validateSecurityRequirements(config: EnvironmentVariables) {
  const errors: string[] = [];

  // Production security checks
  if (config.NODE_ENV === 'production') {
    if (config.JWT_SECRET.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters in production');
    }

    if (config.SESSION_SECRET.length < 32) {
      errors.push(
        'SESSION_SECRET must be at least 32 characters in production',
      );
    }

    if (config.JWT_SECRET === 'fallback-secret-key') {
      errors.push('JWT_SECRET cannot use fallback value in production');
    }

    if (config.SESSION_SECRET === 'fallback-session-secret') {
      errors.push('SESSION_SECRET cannot use fallback value in production');
    }

    if (!config.FRONTEND_URL || config.FRONTEND_URL.includes('localhost')) {
      errors.push('FRONTEND_URL must be set to production URL');
    }

    if (!config.TRUST_PROXY) {
      console.warn(
        '⚠️  Consider setting TRUST_PROXY=true if behind a reverse proxy',
      );
    }
  }

  // MongoDB URI validation
  if (
    !config.MONGODB_URI.startsWith('mongodb://') &&
    !config.MONGODB_URI.startsWith('mongodb+srv://')
  ) {
    errors.push('MONGODB_URI must be a valid MongoDB connection string');
  }

  // Google OAuth validation (if Google auth is enabled)
  if (config.GOOGLE_CLIENT_ID || config.GOOGLE_CLIENT_SECRET) {
    if (!config.GOOGLE_CLIENT_ID || !config.GOOGLE_CLIENT_SECRET) {
      errors.push(
        'Both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be provided for Google OAuth',
      );
    }

    if (!config.GOOGLE_CALLBACK_URL) {
      errors.push('GOOGLE_CALLBACK_URL must be provided for Google OAuth');
    }
  }

  // Email configuration validation (if email is enabled)
  if (config.EMAIL_HOST) {
    if (!config.EMAIL_USER || !config.EMAIL_PASS || !config.EMAIL_FROM) {
      errors.push(
        'EMAIL_USER, EMAIL_PASS, and EMAIL_FROM must be provided when EMAIL_HOST is set',
      );
    }
  }

  if (errors.length > 0) {
    throw new Error(`Security validation failed: ${errors.join('; ')}`);
  }
}

export function logEnvironmentInfo(config: EnvironmentVariables) {
  console.log('🔧 Environment Configuration:');
  console.log(`   NODE_ENV: ${config.NODE_ENV}`);
  console.log(`   PORT: ${config.PORT}`);
  console.log(`   FRONTEND_URL: ${config.FRONTEND_URL}`);
  console.log(
    `   DATABASE: ${config.MONGODB_URI.replace(/\/\/.*@/, '//***:***@')}`,
  );
  console.log(`   JWT_EXPIRES_IN: ${config.JWT_EXPIRES_IN}`);
  console.log(
    `   GOOGLE_AUTH: ${config.GOOGLE_CLIENT_ID ? 'Enabled' : 'Disabled'}`,
  );
  console.log(`   EMAIL: ${config.EMAIL_HOST ? 'Enabled' : 'Disabled'}`);
  console.log(`   TRUST_PROXY: ${config.TRUST_PROXY}`);
  console.log(`   API_DOCS: ${config.ENABLE_API_DOCS}`);
}
