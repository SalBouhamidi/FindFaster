import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  Logger,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Request } from 'express';
import { UsersRepository } from '../../users/repositories/users.repository';
import { CreateUserDto as UsersCreateUserDto } from '../../users/dtos/create-user.dto';
import { GoogleAuthDto } from '../dtos/google-auth.dto';
import { RegisterDto } from '../dtos/register.dto';
import {
  AuthenticatedUser,
  AuthResponse,
  JwtPayload,
  TokenRefreshResponse,
  TokenDocument,
} from '../interfaces/auth.interface';
import { TokenService } from '../../tokens/services/token.service';
import { EmailService } from '../../email/services/email.service';
import { AccountLockoutGuard } from '../../common/guards/account-lockout.guard';
import { SessionCoordinatorService } from '../../sessions/services/session-coordinator.service';
import { objectIdToString } from '../../common/utils/type-guards';
import { Types } from 'mongoose';
import { OAuth2Client } from 'google-auth-library';

/**
 * Authentication service
 * Handles user authentication and JWT token management
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly saltRounds = 12; // Increased from 10 for better security
  private readonly accessTokenExpiry = '15m'; // Short-lived access tokens
  private readonly refreshTokenExpiry = '7d'; // Long-lived refresh tokens

  constructor(
    private usersRepository: UsersRepository,
    private jwtService: JwtService,
    private tokenService: TokenService,
    private emailService: EmailService,
    private sessionCoordinator: SessionCoordinatorService,
    @Inject(forwardRef(() => AccountLockoutGuard))
    private accountLockoutGuard: AccountLockoutGuard,
  ) {}

  /**
   * Handle Google OAuth user creation or login
   * @param googleUser Google user data
   * @param authPreferences User preferences from frontend
   * @returns Authentication response with user and token
   */
  async googleAuth(
    googleUser: {
      googleId: string;
      fullName: string;
      email: string;
      profilePicture?: string;
    },
    authPreferences: GoogleAuthDto,
    request?: Request,
  ): Promise<AuthResponse> {
    // Validate terms acceptance
    if (!authPreferences.termsAccepted) {
      throw new BadRequestException(
        'Terms of service must be accepted to proceed',
      );
    }

    // Check if user already exists
    let user = await this.usersRepository.findByGoogleId(googleUser.googleId);

    if (!user) {
      // Check if email is already registered with different provider
      const existingUser = await this.usersRepository.findByEmail(
        googleUser.email,
      );
      if (existingUser) {
        throw new ConflictException(
          'An account with this email already exists',
        );
      }

      // Create new user
      const createUserDto: UsersCreateUserDto = {
        fullName: googleUser.fullName,
        email: googleUser.email,
        googleId: googleUser.googleId,
        profilePicture: googleUser.profilePicture,
        emailVerified: true, // Google users are pre-verified
        isActive: true,
      };

      user = await this.usersRepository.create(createUserDto);
    } else {
      // Update last login for existing user
      await this.usersRepository.updateLastLogin(objectIdToString(user._id));
    }

    // Prepare user response
    const authenticatedUser: AuthenticatedUser = {
      id: objectIdToString(user._id),
      fullName: user.fullName,
      email: user.email,
      googleId: user.googleId,
      profilePicture: user.profilePicture,
      role: user.role,
      termsAccepted: user.termsAccepted,
      subscribeUpdates: user.subscribeUpdates,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
    };

    // Generate tokens with request for session creation
    const tokens = await this.generateTokens(authenticatedUser, request);

    return {
      user: authenticatedUser,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn,
    };
  }

  /**
   * Register a new user
   * @param registerDto Registration data
   * @param request Optional request for session creation
   * @returns Authentication response with user and token
   */
  async register(
    registerDto: RegisterDto,
    request?: Request,
  ): Promise<AuthResponse> {
    // Check if user already exists
    const existingUser = await this.usersRepository.findByEmail(
      registerDto.email,
    );
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Validate terms acceptance
    if (!registerDto.termsAccepted) {
      throw new BadRequestException(
        'Terms of service must be accepted to proceed',
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(
      registerDto.password,
      this.saltRounds,
    );

    // Create user
    const createUserDto: UsersCreateUserDto = {
      fullName: registerDto.fullName,
      email: registerDto.email,
      password: hashedPassword,
      emailVerified: false,
      isActive: true,
    };

    const user = await this.usersRepository.create(createUserDto);

    // Send email verification automatically
    try {
      const verificationToken =
        await this.tokenService.createEmailVerificationToken(
          objectIdToString(user._id),
        );
      this.logger.log(
        `Authenfication verify token ${verificationToken} during registration`,
      );
      await this.emailService.sendEmailVerification(
        objectIdToString(user._id),
        user.email,
        user.fullName,
        verificationToken,
      );

      // No need to log the result as it is void

      this.logger.log(
        `Verification email sent to ${user.email} during registration`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to send verification email during registration: ${error}`,
      );
      // Don't fail registration if email fails, just log the error
    }

    // Prepare user response
    const authenticatedUser: AuthenticatedUser = {
      id: objectIdToString(user._id),
      fullName: user.fullName,
      email: user.email,
      googleId: user.googleId,
      profilePicture: user.profilePicture,
      role: user.role,
      termsAccepted: user.termsAccepted,
      subscribeUpdates: user.subscribeUpdates,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
    };

    // Generate tokens with request for session creation
    const tokens = await this.generateTokens(authenticatedUser, request);

    return {
      user: authenticatedUser,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn,
    };
  }

  /**
   * Login user with email and password
   * @param email User email
   * @param password User password
   * @param request Express request for security tracking
   * @returns Authentication response with user and token
   */
  async login(
    email: string,
    password: string,
    request?: Request,
  ): Promise<AuthResponse> {
    const normalizedEmail = email.toLowerCase().trim();

    try {
      const user = await this.validateLocalUser(normalizedEmail, password);

      if (!user) {
        // Record failed attempt for security tracking
        if (request) {
          await this.accountLockoutGuard.recordFailedAttempt(
            request,
            normalizedEmail,
          );
        }

        // Log failed attempt
        this.logger.warn(`Failed login attempt for ${normalizedEmail}`, {
          ip: request ? this.getClientIP(request) : 'unknown',
          userAgent: request?.headers['user-agent'] || 'unknown',
        });

        throw new UnauthorizedException('Invalid email or password');
      }

      // Check if account is locked in database
      if (user.isActive === false) {
        throw new UnauthorizedException('Account is deactivated');
      }

      // Record successful attempt
      if (request) {
        this.accountLockoutGuard.recordSuccessfulAttempt(
          request,
          normalizedEmail,
        );
      }

      // Update last login with security info
      await this.updateLastLoginWithSecurityInfo(user.id, request);

      // Generate JWT tokens with request for session creation
      const tokens = await this.generateTokens(user, request);

      // After creating the session, check and enforce the session limit
      await this.sessionCoordinator.enforceSessionLimit(user.id);

      // Log successful login
      this.logger.log(`Successful login for ${normalizedEmail}`, {
        userId: user.id,
        ip: request ? this.getClientIP(request) : 'unknown',
      });

      return {
        user,
        ...tokens,
      };
    } catch (error) {
      // Check if this should trigger permanent account lock
      if (request) {
        await this.accountLockoutGuard.checkForPermanentLock(normalizedEmail);
      }
      throw error;
    }
  }

  /**
   * Validate user credentials for local authentication
   * @param email User email
   * @param password User password
   * @returns Authenticated user or null
   */
  async validateLocalUser(
    email: string,
    password: string,
  ): Promise<AuthenticatedUser | null> {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.usersRepository.findByEmail(normalizedEmail);

    if (!user || !user.password || !user.isActive || user.isLocked) {
      return null;
    }

    // Add timing attack protection
    const isPasswordValid = await this.securePasswordCompare(
      password,
      user.password,
    );

    if (!isPasswordValid) {
      return null;
    }

    return {
      id: objectIdToString(user._id),
      fullName: user.fullName,
      email: user.email,
      googleId: user.googleId,
      profilePicture: user.profilePicture,
      role: user.role,
      termsAccepted: user.termsAccepted,
      subscribeUpdates: user.subscribeUpdates,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
    };
  }

  /**
   * Secure password comparison with timing attack protection
   */
  private async securePasswordCompare(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    try {
      return await bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      // Log error but don't reveal it
      this.logger.error('Password comparison error', error);
      return false;
    }
  }

  /**
   * Update last login with additional security information
   */
  private async updateLastLoginWithSecurityInfo(
    userId: string,
    request?: Request,
  ): Promise<void> {
    try {
      await this.usersRepository.updateLastLogin(userId);

      // Log additional security info (could be stored in separate security log)
      if (request) {
        this.logger.log('User login details', {
          userId,
          ip: this.getClientIP(request),
          userAgent: request.headers['user-agent'],
          timestamp: new Date(),
        });
      }
    } catch (error) {
      this.logger.error('Failed to update last login', error);
    }
  }

  /**
   * Get client IP address from request
   */
  private getClientIP(request: Request): string {
    return (
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (request.headers['x-real-ip'] as string) ||
      request.connection?.remoteAddress ||
      request.socket?.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Generate JWT tokens for user
   * @param user User data
   * @returns JWT tokens
   */
  async generateTokens(
    user: AuthenticatedUser,
    request?: Request,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    // Generate refresh token first with jti placeholder
    const tempTokenId = new Types.ObjectId().toString();

    const refreshTokenPayload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      type: 'refresh',
      jti: tempTokenId,
    };

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      expiresIn: this.refreshTokenExpiry,
    });

    // Store refresh token in database with the actual token
    const tokenDoc = (await this.tokenService.createRefreshToken(
      user.id,
      refreshToken,
    )) as TokenDocument;

    // Generate access token with the actual jti from database
    const accessTokenPayload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      type: 'access',
      jti: tokenDoc._id.toString(), // Use actual database ID
    };

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      expiresIn: this.accessTokenExpiry,
    });

    // Re-sign refresh token with the actual database ID
    const finalRefreshTokenPayload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      type: 'refresh',
      jti: tokenDoc._id.toString(), // Use actual database ID
    };

    const finalRefreshToken = this.jwtService.sign(finalRefreshTokenPayload, {
      expiresIn: this.refreshTokenExpiry,
    });

    // Create session record if request is provided
    if (request && tokenDoc && tokenDoc._id) {
      try {
        const deviceInfo = this.sessionCoordinator.generateDeviceInfo(request);
        const tokenId =
          typeof tokenDoc._id === 'string'
            ? tokenDoc._id
            : tokenDoc._id.toString();

        await this.sessionCoordinator.createSession(
          user.id,
          tokenId,
          deviceInfo,
          request,
        );
        // Log session creation
        this.logger.log(
          `Session created for user ${user.id} on ${deviceInfo.deviceType} device`,
        );
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : 'Unknown error';
        this.logger.warn(`Failed to create session record: ${errorMessage}`);
      }
    }

    // Calculate expiration time in seconds
    const expiresIn = 15 * 60; // 15 minutes

    return {
      accessToken,
      refreshToken: finalRefreshToken,
      expiresIn,
    };
  }

  /**
   * Refresh access token using refresh token
   * @param refreshToken Refresh token
   * @returns New tokens
   */
  async refreshTokens(refreshToken: string): Promise<TokenRefreshResponse> {
    try {
      // Verify refresh token
      const rawPayload: unknown = this.jwtService.verify(refreshToken);

      if (!this.isValidJwtPayload(rawPayload)) {
        throw new UnauthorizedException('Invalid token payload');
      }

      const payload: JwtPayload = rawPayload;

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Validate the presented refresh token against storage (hashed in DB)
      const userIdFromToken =
        await this.tokenService.verifyRefreshToken(refreshToken);

      if (!userIdFromToken || userIdFromToken !== payload.sub) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Get user data
      const user = await this.validateUser(payload.sub);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new tokens and rotate refresh token
      const tokens = await this.generateTokens(user);
      // Invalidate the presented (old) refresh token
      await this.tokenService.invalidateRefreshToken(refreshToken);

      return tokens;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Revoke refresh token (logout)
   * @param userId User ID
   */
  async revokeRefreshToken(userId: string): Promise<void> {
    await this.tokenService.invalidateRefreshToken(userId);
  }

  /**
   * Revoke all refresh tokens for user (logout from all devices)
   * @param userId User ID
   */
  async revokeAllRefreshTokens(userId: string): Promise<void> {
    await this.tokenService.invalidateAllRefreshTokens(userId);
  }

  /**
   * Get user profile by ID
   * @param userId User ID
   * @returns User profile
   */
  async getUserProfile(userId: string): Promise<AuthenticatedUser> {
    const user = await this.usersRepository.findById(userId);

    if (!user || !user.isActive) {
      throw new UnauthorizedException('User not found or inactive');
    }

    return {
      id: objectIdToString(user._id),
      fullName: user.fullName,
      email: user.email,
      googleId: user.googleId,
      profilePicture: user.profilePicture,
      role: user.role,
      termsAccepted: user.termsAccepted,
      subscribeUpdates: user.subscribeUpdates,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
    };
  }

  /**
   * Validate user exists and is active
   * @param userId User ID
   * @returns User or null
   */
  private async validateUser(
    userId: string,
  ): Promise<AuthenticatedUser | null> {
    try {
      return await this.getUserProfile(userId);
    } catch {
      return null;
    }
  }

  /**
   * Validate JWT payload structure
   * @param payload JWT payload
   * @returns True if valid
   */
  private isValidJwtPayload(payload: unknown): payload is JwtPayload {
    return (
      typeof payload === 'object' &&
      payload !== null &&
      'sub' in payload &&
      'email' in payload &&
      'role' in payload
    );
  }

  /**
   * Send forgot password email
   * @param email User email
   * @returns Success message
   */
  async forgotPassword(email: string): Promise<{ message: string }> {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.usersRepository.findByEmail(normalizedEmail);

    if (user) {
      try {
        const resetToken = await this.tokenService.createPasswordResetToken(
          objectIdToString(user._id),
        );

        await this.emailService.sendPasswordReset(
          user.email,
          user.fullName,
          resetToken,
        );

        this.logger.log(`Password reset email sent to ${email}`);
      } catch (error) {
        this.logger.error(`Failed to send password reset email: ${error}`);
        // Don't reveal if user exists
      }
    }

    return {
      message: 'If the email exists, a reset link has been sent',
    };
  }

  /**
   * Reset password with token
   * @param token Reset token
   * @param newPassword New password
   * @returns Success message
   */
  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    // Find user by reset token
    const userId = await this.tokenService.findUserByPasswordResetToken(token);

    if (!userId) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, this.saltRounds);

    // Update user password
    await this.usersRepository.updatePassword(userId, hashedPassword);

    // Invalidate reset token
    await this.tokenService.verifyPasswordResetToken(token);

    this.logger.log(`Password reset successful for user ${userId}`);

    return {
      message: 'Password reset successfully',
    };
  }

  /**
   * Send email verification
   * @param userId User ID
   * @returns Success message
   */
  async sendEmailVerification(userId: string): Promise<{ message: string }> {
    const user = await this.usersRepository.findById(userId);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email already verified');
    }

    try {
      const verificationToken =
        await this.tokenService.createEmailVerificationToken(userId);

      await this.emailService.sendEmailVerification(
        userId,
        user.email,
        user.fullName,
        verificationToken,
      );

      this.logger.log(`Verification email sent to ${user.email}`);
    } catch (error) {
      this.logger.error(`Failed to send verification email: ${error}`);
      throw new BadRequestException('Failed to send verification email');
    }

    return {
      message: 'Verification email sent',
    };
  }

  /**
   * Verify email with token
   * @param token Verification token
   * @returns Success message
   */
  async verifyEmail(token: string): Promise<{ message: string }> {
    // Find user by verification token
    const userId =
      await this.tokenService.findUserByEmailVerificationToken(token);

    if (!userId) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Verify the token
    const isValid = await this.tokenService.verifyEmailVerificationToken(token);

    if (!isValid) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Update user email verification status
    await this.usersRepository.verifyEmail(userId);

    this.logger.log(`Email verified for user ${userId}`);

    return {
      message: 'Email verified successfully',
    };
  }

  /**
   * Send new device login alert
   * @param userId User ID
   * @param deviceInfo Device information
   * @param request Express request for IP and user agent
   * @returns Success message
   */
  async sendNewDeviceLoginAlert(
    userId: string,
    deviceInfo: {
      browser?: string;
      os?: string;
      ip?: string;
      location?: string;
    },
    request?: Request,
  ): Promise<{ message: string }> {
    const user = await this.usersRepository.findById(userId);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Get IP from request if available
    const ip = request ? this.getClientIP(request) : 'Unknown';

    // Send new device login alert
    await this.emailService.sendNewDeviceLoginAlert(
      user.email,
      user.fullName,
      {
        browser: deviceInfo.browser || 'Unknown Browser',
        os: deviceInfo.os || 'Unknown OS',
        ip: deviceInfo.ip || ip,
        location: deviceInfo.location || 'Unknown Location',
      },
      new Date(),
    );

    this.logger.log(
      `New device login alert sent to ${user.email} for user ${userId}`,
    );

    return { message: 'New device login alert sent' };
  }

  /**
   * Send account locked notification
   * @param userId User ID
   * @param reason Lock reason
   * @returns Success message
   */
  async sendAccountLockedNotification(
    userId: string,
    reason: string,
  ): Promise<{ message: string }> {
    const user = await this.usersRepository.findById(userId);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Send account locked notification
    await this.emailService.sendAccountLocked(
      user.email,
      user.fullName,
      reason,
      new Date(),
    );

    this.logger.log(
      `Account locked notification sent to ${user.email} for user ${userId}`,
    );

    return { message: 'Account locked notification sent' };
  }

  /**
   * Send password change confirmation
   * @param userId User ID
   * @param deviceInfo Device information
   * @param request Express request for IP and user agent
   * @returns Success message
   */
  async sendPasswordChangeConfirmation(
    userId: string,
    deviceInfo?: {
      browser?: string;
      os?: string;
      ip?: string;
    },
    request?: Request,
  ): Promise<{ message: string }> {
    const user = await this.usersRepository.findById(userId);

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Get IP from request if available
    const ip = request ? this.getClientIP(request) : 'Unknown';

    // Send password change confirmation
    await this.emailService.sendPasswordChangeConfirmation(
      user.email,
      user.fullName,
      {
        browser: deviceInfo?.browser || 'Unknown Browser',
        os: deviceInfo?.os || 'Unknown OS',
        ip: deviceInfo?.ip || ip,
      },
      new Date(),
    );

    this.logger.log(
      `Password change confirmation sent to ${user.email} for user ${userId}`,
    );

    return { message: 'Password change confirmation sent' };
  }

  async verifyGoogleToken(token: string): Promise<{
    googleId: string;
    fullName: string;
    email: string;
    profilePicture?: string;
  }> {
    try {
      const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      if (!payload) {
        throw new BadRequestException('Invalid Google token payload');
      }

      return {
        googleId: payload.sub,
        fullName: payload.name || '',
        email: payload.email || '',
        profilePicture: payload.picture,
      };
    } catch (error) {
      this.logger.error('Google token verification failed:', error);
      throw new BadRequestException('Invalid Google token');
    }
  }
 /**
   * Checks if a user has a premium (paid) status.
   * This method will be called by the AuthController for the extension's payment check.
   * @param userId The ID of the user to check.
   * @returns A boolean indicating if the user is a premium (paid) user.
   */

async checkUserPaymentStatus(userId: string): Promise<boolean> {
  this.logger.log(`Checking payment status for user ID: ${userId}`);

  const user = await this.usersRepository.findById(userId);

  if (!user || !user.isActive) {
    this.logger.warn(`User ${userId} not found or inactive during payment check.`);
    return false;
  }

  
  return user.isPremium === true;
}
}

