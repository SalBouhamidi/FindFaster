import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import { UsersRepository } from '../../users/repositories/users.repository';
import { EmailService } from '../../email/services/email.service';
import {
  hasProperty,
  isString,
  objectIdToString,
} from '../utils/type-guards';
import { ObjectId } from 'mongoose';

interface LoginAttempt {
  email: string;
  ip: string;
  userAgent: string;
  timestamp: Date;
  success: boolean;
}

interface AccountLockInfo {
  failedAttempts: number;
  firstFailedAttempt: Date;
  lockedUntil?: Date;
  lockReason?: string;
}

/**
 * Account lockout guard that tracks failed login attempts per user account
 * Implements progressive lockout periods and security notifications
 */
@Injectable()
export class AccountLockoutGuard implements CanActivate {
  private readonly logger = new Logger(AccountLockoutGuard.name);
  private readonly loginAttempts = new Map<string, AccountLockInfo>();

  // Lockout configuration
  private readonly MAX_FAILED_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION_MINUTES = 30;
  private readonly PROGRESSIVE_LOCKOUT_MULTIPLIER = 2;
  private readonly ATTEMPT_WINDOW_MINUTES = 15;

  constructor(
    private readonly usersRepository: UsersRepository,
    private readonly emailService: EmailService,
  ) {
    // Clean up old entries every hour
    setInterval(() => this.cleanup(), 60 * 60 * 1000);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    if (!hasProperty(request.body, 'email') || !isString(request.body.email)) {
      return true; // Let other validators handle missing email
    }

    const email = request.body.email.toLowerCase().trim();

    // Check if account exists and is locked in database
    const user = await this.usersRepository.findByEmail(email);
    if (user?.isLocked) {
      throw new HttpException(
        {
          message: 'Account is locked. Please contact support for assistance.',
          reason: 'account_locked',
        },
        HttpStatus.FORBIDDEN,
      );
    }

    // Check temporary lockout from failed attempts
    const lockInfo = this.loginAttempts.get(email);
    if (lockInfo && this.isTemporarilyLocked(lockInfo)) {
      const remainingTime = this.getRemainingLockTime(lockInfo);
      throw new HttpException(
        {
          message: `Account temporarily locked due to multiple failed attempts. Try again in ${remainingTime} minutes.`,
          reason: 'temporary_lockout',
          retryAfter: remainingTime * 60,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  /**
   * Record a failed login attempt
   */
  async recordFailedAttempt(request: Request, email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    const ip = this.getClientIP(request);
    const userAgent = request.headers['user-agent'] || '';

    // Log the failed attempt
    this.logger.warn(`Failed login attempt for ${normalizedEmail} from ${ip}`);

    // Update attempt tracking
    const lockInfo = this.loginAttempts.get(normalizedEmail) || {
      failedAttempts: 0,
      firstFailedAttempt: new Date(),
    };

    // Reset if outside attempt window
    const windowStart = new Date(
      Date.now() - this.ATTEMPT_WINDOW_MINUTES * 60 * 1000,
    );
    if (lockInfo.firstFailedAttempt < windowStart) {
      lockInfo.failedAttempts = 0;
      lockInfo.firstFailedAttempt = new Date();
      delete lockInfo.lockedUntil;
    }

    lockInfo.failedAttempts++;

    // Check if we should lock the account
    if (lockInfo.failedAttempts >= this.MAX_FAILED_ATTEMPTS) {
      await this.lockAccount(normalizedEmail, lockInfo, request);
    }

    this.loginAttempts.set(normalizedEmail, lockInfo);

    // Log attempt details for security monitoring
    const attempt: LoginAttempt = {
      email: normalizedEmail,
      ip,
      userAgent,
      timestamp: new Date(),
      success: false,
    };

    this.logSecurityEvent('failed_login_attempt', attempt);
  }

  /**
   * Record a successful login attempt
   */
  recordSuccessfulAttempt(request: Request, email: string): void {
    const normalizedEmail = email.toLowerCase().trim();
    const ip = this.getClientIP(request);
    const userAgent = request.headers['user-agent'] || '';

    // Clear failed attempts on successful login
    this.loginAttempts.delete(normalizedEmail);

    // Log successful attempt
    const attempt: LoginAttempt = {
      email: normalizedEmail,
      ip,
      userAgent,
      timestamp: new Date(),
      success: true,
    };

    this.logSecurityEvent('successful_login', attempt);
    this.logger.log(`Successful login for ${normalizedEmail} from ${ip}`);
  }

  /**
   * Check if account should be permanently locked
   */
  async checkForPermanentLock(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    const lockInfo = this.loginAttempts.get(normalizedEmail);

    if (!lockInfo) return;

    // Implement progressive lockout or permanent lock based on severity
    if (lockInfo.failedAttempts >= this.MAX_FAILED_ATTEMPTS * 3) {
      // Too many attempts - lock account permanently
      await this.permanentlyLockAccount(
        normalizedEmail,
        'excessive_failed_attempts',
      );
    }
  }

  private async lockAccount(
    email: string,
    lockInfo: AccountLockInfo,
    request: Request,
  ): Promise<void> {
    const lockDurationMs = this.calculateLockDuration(lockInfo.failedAttempts);
    lockInfo.lockedUntil = new Date(Date.now() + lockDurationMs);
    lockInfo.lockReason = 'failed_login_attempts';

    const lockDurationMinutes = Math.ceil(lockDurationMs / (60 * 1000));

    this.logger.warn(
      `Account ${email} temporarily locked for ${lockDurationMinutes} minutes after ${lockInfo.failedAttempts} failed attempts`,
    );

    // Send security notification email
    try {
      const user = await this.usersRepository.findByEmail(email);
      if (user && user.emailVerified) {
        await this.emailService.sendAccountLocked(
          user.email,
          user.fullName,
          `${lockInfo.failedAttempts} failed login attempts in ${this.ATTEMPT_WINDOW_MINUTES} minutes`,
          new Date(),
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to send lockout notification email: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }

    // Log security event
    this.logSecurityEvent('account_temporarily_locked', {
      email,
      failedAttempts: lockInfo.failedAttempts,
      lockDurationMinutes,
      ip: this.getClientIP(request),
    });
  }

  private async permanentlyLockAccount(
    email: string,
    reason: string,
  ): Promise<void> {
    try {
      const user = await this.usersRepository.findByEmail(email);
      if (user) {
        await this.usersRepository.lockAccount(
          objectIdToString(user._id as ObjectId),
        );
        this.logger.error(`Account ${email} permanently locked: ${reason}`);

        // Send critical security alert
        if (user.emailVerified) {
          await this.emailService.sendAccountLocked(
            user.email,
            user.fullName,
            `Account permanently locked due to ${reason}`,
            new Date(),
          );
        }

        this.logSecurityEvent('account_permanently_locked', {
          email,
          reason,
          timestamp: new Date(),
        });
      }
    } catch (error) {
      this.logger.error(
        `Failed to permanently lock account ${email}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  private calculateLockDuration(attemptCount: number): number {
    const baseDuration = this.LOCKOUT_DURATION_MINUTES * 60 * 1000; // Convert to ms
    const multiplier = Math.pow(
      this.PROGRESSIVE_LOCKOUT_MULTIPLIER,
      attemptCount - this.MAX_FAILED_ATTEMPTS,
    );
    return Math.min(baseDuration * multiplier, 24 * 60 * 60 * 1000); // Max 24 hours
  }

  private isTemporarilyLocked(lockInfo: AccountLockInfo): boolean {
    if (!lockInfo.lockedUntil) return false;
    return new Date() < lockInfo.lockedUntil;
  }

  private getRemainingLockTime(lockInfo: AccountLockInfo): number {
    if (!lockInfo.lockedUntil) return 0;
    const remaining = lockInfo.lockedUntil.getTime() - Date.now();
    return Math.ceil(remaining / (60 * 1000)); // Convert to minutes
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

  private logSecurityEvent(eventType: string, data: any): void {
    // This should ideally go to a security monitoring system
    // For now, we'll use structured logging
    this.logger.warn(`SECURITY_EVENT: ${eventType}`, {
      eventType,
      timestamp: new Date(),
      ...data,
    });
  }

  private cleanup(): void {
    const cutoffTime = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago

    for (const [email, lockInfo] of this.loginAttempts.entries()) {
      // Remove old entries that are no longer relevant
      if (
        lockInfo.firstFailedAttempt < cutoffTime &&
        (!lockInfo.lockedUntil || lockInfo.lockedUntil < new Date())
      ) {
        this.loginAttempts.delete(email);
      }
    }
  }
}
