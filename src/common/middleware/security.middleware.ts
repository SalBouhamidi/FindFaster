import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { isObject } from '@common/utils/type-guards';

/**
 * Security middleware that adds security headers and implements basic protections
 */
@Injectable()
export class SecurityMiddleware implements NestMiddleware {
  private readonly logger = new Logger(SecurityMiddleware.name);

  use(req: Request, res: Response, next: NextFunction): void {
    // Security Headers
    this.setSecurityHeaders(res);

    // Log suspicious requests
    this.logSuspiciousActivity(req);

    // Rate limit headers (if needed)
    this.setRateLimitHeaders(res);

    next();
  }

  private setSecurityHeaders(res: Response): void {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Enable XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Content Security Policy
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self' data:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none';",
    );

    // Strict Transport Security (HTTPS only)
    if (process.env.NODE_ENV === 'production') {
      res.setHeader(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload',
      );
    }

    // Hide server information
    res.removeHeader('X-Powered-By');
    res.setHeader('Server', 'FindFaster');

    // Permissions Policy (formerly Feature Policy)
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=()',
    );
  }

  private logSuspiciousActivity(req: Request): void {
    const suspiciousPatterns = [
      /\.\./, // Directory traversal
      /<script/i, // XSS attempts
      /union.*select/i, // SQL injection
      /javascript:/i, // JavaScript protocol
      /on\w+\s*=/i, // Event handlers
    ];

    const url = req.url;
    const userAgent = req.headers['user-agent'] || '';
    const body = JSON.stringify(req.body);

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url) || pattern.test(userAgent) || pattern.test(body)) {
        this.logger.warn(`Suspicious request detected`, {
          ip: this.getClientIP(req),
          url,
          userAgent,
          method: req.method,
          pattern: pattern.toString(),
        });
        break;
      }
    }
  }

  private setRateLimitHeaders(res: Response): void {
    // These can be dynamically set based on actual rate limiting
    res.setHeader('X-RateLimit-Limit', '100');
    res.setHeader('X-RateLimit-Remaining', '99');
    res.setHeader('X-RateLimit-Reset', Math.floor(Date.now() / 1000) + 3600);
  }

  private getClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      'unknown'
    );
  }
}

/**
 * CSRF Protection Middleware
 * Simple implementation for stateless JWT APIs
 */
@Injectable()
export class CSRFProtectionMiddleware implements NestMiddleware {
  private readonly logger = new Logger(CSRFProtectionMiddleware.name);

  use(req: Request, res: Response, next: NextFunction): void {
    // Skip CSRF for GET, HEAD, OPTIONS requests
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next();
    }

    // For API routes with JWT, check for proper headers
    if (req.path.startsWith('/api/')) {
      const contentType = req.headers['content-type'];
      const origin = req.headers.origin;
      const referer = req.headers.referer;

      // Ensure JSON content type for API requests
      if (!contentType?.includes('application/json')) {
        this.logger.warn(
          `Invalid content type for API request: ${contentType}`,
          {
            ip: this.getClientIP(req),
            path: req.path,
            method: req.method,
          },
        );
      }

      // Check origin/referer for CSRF protection
      if (process.env.NODE_ENV === 'production') {
        const allowedOrigins = [
          process.env.FRONTEND_URL,
          process.env.ADMIN_URL,
        ].filter(Boolean) as string[];

        const isValidOrigin =
          origin &&
          allowedOrigins.some((allowed) => origin.startsWith(allowed));

        const isValidReferer =
          referer &&
          allowedOrigins.some((allowed) => referer.startsWith(allowed));

        if (!isValidOrigin && !isValidReferer) {
          this.logger.error(`CSRF protection triggered`, {
            ip: this.getClientIP(req),
            origin,
            referer,
            path: req.path,
            method: req.method,
          });

          res.status(403).json({
            message: 'Forbidden: Invalid origin',
            error: 'CSRF_PROTECTION',
          });
          return;
        }
      }
    }

    next();
  }

  private getClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      'unknown'
    );
  }
}

/**
 * Request sanitization middleware
 */
@Injectable()
export class RequestSanitizationMiddleware implements NestMiddleware {
  private readonly logger = new Logger(RequestSanitizationMiddleware.name);

  use(req: Request, res: Response, next: NextFunction): void {
    // Sanitize request body
    if (isObject(req.body)) {
      req.body = this.sanitizeObject(req.body);
    }

    // Sanitize query parameters
    if (isObject(req.query)) {
      this.sanitizeObjectInPlace(req.query as Record<string, unknown>);
    }

    next();
  }

  private sanitizeObject<T>(obj: T): T {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map((item: unknown) => this.sanitizeObject(item)) as T;
    }

    if (typeof obj === 'object') {
      const sanitized: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(
        obj as Record<string, unknown>,
      )) {
        // Skip potentially dangerous keys
        if (this.isDangerousKey(key)) {
          this.logger.warn(`Blocked dangerous key: ${key}`);
          continue;
        }
        sanitized[key] = this.sanitizeObject(value);
      }
      return sanitized as T;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj) as T;
    }

    return obj;
  }

  private sanitizeString(str: string): string {
    // Remove null bytes and control characters
    // eslint-disable-next-line no-control-regex
    return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  }

  private isDangerousKey(key: string): boolean {
    const dangerousKeys = [
      '__proto__',
      'constructor',
      'prototype',
      '__defineGetter__',
      '__defineSetter__',
      '__lookupGetter__',
      '__lookupSetter__',
    ];
    return dangerousKeys.includes(key);
  }

  private sanitizeObjectInPlace(obj: Record<string, unknown>): void {
    for (const key of Object.keys(obj)) {
      if (this.isDangerousKey(key)) {
        delete obj[key];
        continue;
      }
      const value = obj[key];
      if (value === null || value === undefined) {
        continue;
      }
      if (Array.isArray(value)) {
        obj[key] = value.map((item: unknown) =>
          typeof item === 'string' ? this.sanitizeString(item) : item,
        );
        continue;
      }
      if (typeof value === 'object') {
        this.sanitizeObjectInPlace(value as Record<string, unknown>);
        continue;
      }
      if (typeof value === 'string') {
        obj[key] = this.sanitizeString(value);
      }
    }
  }
}
