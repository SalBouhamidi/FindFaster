import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { isObject } from '../utils/type-guards';

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

interface RateLimitOptions {
  windowMs: number; // Time window in milliseconds
  maxAttempts: number; // Maximum attempts per window
  blockDurationMs?: number; // Block duration after max attempts (default: windowMs)
  skipSuccessfulRequests?: boolean; // Reset counter on successful requests
}

const DEFAULT_RATE_LIMIT: RateLimitOptions = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 5,
  blockDurationMs: 30 * 60 * 1000, // 30 minutes
  skipSuccessfulRequests: true,
};

/**
 * Rate limiting guard to prevent brute force attacks
 * Tracks failed attempts per IP address and implements exponential backoff
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private attempts = new Map<string, RateLimitEntry>();
  private blockedIPs = new Map<string, number>(); // IP -> unblock timestamp

  constructor(private reflector: Reflector) {
    // Clean up old entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  canActivate(context: ExecutionContext): boolean {
    const options = this.getRateLimitOptions(context);
    const request = context.switchToHttp().getRequest<Request>();
    const key = this.getKey(request);

    // Check if IP is currently blocked
    if (this.isBlocked(key)) {
      throw new HttpException(
        {
          message: 'Too many failed attempts. Account temporarily locked.',
          retryAfter: this.getRetryAfter(key),
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Check rate limit
    if (this.isRateLimited(key, options)) {
      // Block the IP for extended period after too many attempts
      this.blockIP(key, options.blockDurationMs || options.windowMs);

      throw new HttpException(
        {
          message: 'Too many failed attempts. Please try again later.',
          retryAfter: Math.ceil(
            (options.blockDurationMs || options.windowMs) / 1000,
          ),
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  /**
   * Record a failed attempt for the given key
   */
  recordFailedAttempt(request: Request): void {
    const key = this.getKey(request);
    const now = Date.now();
    const options = DEFAULT_RATE_LIMIT;

    const entry = this.attempts.get(key) || {
      count: 0,
      resetTime: now + options.windowMs,
    };

    // Reset if window has expired
    if (now > entry.resetTime) {
      entry.count = 0;
      entry.resetTime = now + options.windowMs;
    }

    entry.count++;
    this.attempts.set(key, entry);
  }

  /**
   * Reset attempts for successful login (if configured)
   */
  recordSuccessfulAttempt(request: Request): void {
    const key = this.getKey(request);
    this.attempts.delete(key);
    this.blockedIPs.delete(key);
  }

  private getRateLimitOptions(context: ExecutionContext): RateLimitOptions {
    const customOptions = this.reflector.get<Partial<RateLimitOptions>>(
      'rateLimit',
      context.getHandler(),
    );
    const validOptions: Partial<RateLimitOptions> = isObject(customOptions)
      ? customOptions
      : {};
    return { ...DEFAULT_RATE_LIMIT, ...validOptions };
  }

  private getKey(request: Request): string {
    // Use a combination of IP and user agent for better accuracy
    const ip = this.getClientIP(request);
    const userAgent = request.headers['user-agent'] || '';
    return `${ip}:${this.hashUserAgent(userAgent)}`;
  }

  private getClientIP(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (request.headers['x-real-ip'] as string) ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  }

  private hashUserAgent(userAgent: string): string {
    // Simple hash for user agent to avoid storing full string
    let hash = 0;
    for (let i = 0; i < userAgent.length; i++) {
      const char = userAgent.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  private isRateLimited(key: string, options: RateLimitOptions): boolean {
    const entry = this.attempts.get(key);
    if (!entry) return false;

    const now = Date.now();

    // Reset if window has expired
    if (now > entry.resetTime) {
      this.attempts.delete(key);
      return false;
    }

    return entry.count >= options.maxAttempts;
  }

  private isBlocked(key: string): boolean {
    const blockedUntil = this.blockedIPs.get(key);
    if (!blockedUntil) return false;

    if (Date.now() > blockedUntil) {
      this.blockedIPs.delete(key);
      return false;
    }

    return true;
  }

  private blockIP(key: string, durationMs: number): void {
    this.blockedIPs.set(key, Date.now() + durationMs);
  }

  private getRetryAfter(key: string): number {
    const blockedUntil = this.blockedIPs.get(key);
    if (!blockedUntil) return 0;
    return Math.ceil((blockedUntil - Date.now()) / 1000);
  }

  private cleanup(): void {
    const now = Date.now();

    // Clean up expired attempts
    for (const [key, entry] of this.attempts.entries()) {
      if (now > entry.resetTime) {
        this.attempts.delete(key);
      }
    }

    // Clean up expired blocks
    for (const [key, blockedUntil] of this.blockedIPs.entries()) {
      if (now > blockedUntil) {
        this.blockedIPs.delete(key);
      }
    }
  }
}

/**
 * Decorator to set rate limit options for specific routes
 */
export const RateLimit =
  (options: Partial<RateLimitOptions>) =>
  (target: object, propertyKey?: string, descriptor?: PropertyDescriptor) => {
    if (descriptor && descriptor.value) {
      Reflect.defineMetadata('rateLimit', options, descriptor.value as object);
      return descriptor;
    }
    Reflect.defineMetadata('rateLimit', options, target);
    return target;
  };
