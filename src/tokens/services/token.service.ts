import { Injectable, Logger } from '@nestjs/common';
import { randomBytes, createHash } from 'crypto';
import { TokenType } from '../schemas/token.schema';
import { TokenRepository } from '../repositories/tokens.repository';
import { getErrorMessage, objectIdToString } from '../../common/utils/type-guards';
import {
  DeviceInfo,
  SessionInfo,
} from '../../sessions/interfaces/session.interface';
import { TokenDocument } from '../schemas/token.schema';

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name);

  constructor(private readonly tokenRepository: TokenRepository) {}

  /**
   * Create a refresh token with device information
   */
  async createRefreshToken(
    userId: string,
    token: string,
    deviceInfo?: DeviceInfo,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<any> {
    try {
      const hashedToken = this.hashToken(token);
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      const tokenDoc = await this.tokenRepository.create({
        userId,
        type: TokenType.REFRESH,
        token: hashedToken,
        expiresAt,
        deviceInfo: deviceInfo ? JSON.stringify(deviceInfo) : undefined,
        ipAddress,
        userAgent,
        isRevoked: false,
      });

      this.logger.log(
        `Refresh token created for user ${userId} on ${deviceInfo?.deviceType || 'unknown'} device`,
      );

      return tokenDoc;
    } catch (error) {
      this.logger.error(
        `Failed to create refresh token: ${getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Create password reset token
   */
  async createPasswordResetToken(userId: string): Promise<string> {
    try {
      const token = this.generateSecureToken();
      const hashedToken = this.hashToken(token);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Remove any existing password reset tokens for this user
      await this.tokenRepository.deleteByUserId(
        userId,
        TokenType.PASSWORD_RESET,
      );

      await this.tokenRepository.create({
        userId,
        type: TokenType.PASSWORD_RESET,
        token: hashedToken,
        expiresAt,
        isRevoked: false,
      });

      this.logger.log(`Password reset token created for user ${userId}`);
      return token; // Return the plain token for email
    } catch (error) {
      this.logger.error(
        `Failed to create password reset token: ${getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Create email verification token
   */
  async createEmailVerificationToken(userId: string): Promise<string> {
    try {
      const token = this.generateSecureToken();
      const hashedToken = this.hashToken(token);
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Remove any existing email verification tokens for this user
      await this.tokenRepository.deleteByUserId(
        userId,
        TokenType.EMAIL_VERIFICATION,
      );

      await this.tokenRepository.create({
        userId,
        type: TokenType.EMAIL_VERIFICATION,
        token: hashedToken,
        expiresAt,
        isRevoked: false,
      });

      this.logger.log(`Email verification token created for user ${userId}`);
      return token; // Return the plain token for email
    } catch (error) {
      this.logger.error(
        `Failed to create email verification token: ${getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Verify a refresh token
   */
  async verifyRefreshToken(token: string): Promise<string | null> {
    try {
      const hashedToken = this.hashToken(token);
      const tokenDoc = await this.tokenRepository.findValidToken(
        hashedToken,
        TokenType.REFRESH,
      );

      if (!tokenDoc) {
        return null;
      }

      // Update last used timestamp
      await this.updateSessionLastUsed(objectIdToString(tokenDoc._id));

      return objectIdToString(tokenDoc.userId);
    } catch (error) {
      this.logger.error(
        `Failed to verify refresh token: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Find user by password reset token
   */
  async findUserByPasswordResetToken(token: string): Promise<string | null> {
    try {
      const hashedToken = this.hashToken(token);
      const tokenDoc = await this.tokenRepository.findValidToken(
        hashedToken,
        TokenType.PASSWORD_RESET,
      );

      return tokenDoc ? objectIdToString(tokenDoc.userId) : null;
    } catch (error) {
      this.logger.error(
        `Failed to find user by password reset token: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Find user by email verification token
   */
  async findUserByEmailVerificationToken(
    token: string,
  ): Promise<string | null> {
    try {
      const hashedToken = this.hashToken(token);
      const tokenDoc = await this.tokenRepository.findValidToken(
        hashedToken,
        TokenType.EMAIL_VERIFICATION,
      );

      return tokenDoc ? objectIdToString(tokenDoc.userId) : null;
    } catch (error) {
      this.logger.error(
        `Failed to find user by email verification token: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Verify password reset token
   */
  async verifyPasswordResetToken(token: string): Promise<boolean> {
    try {
      const hashedToken = this.hashToken(token);
      const tokenDoc = await this.tokenRepository.findValidToken(
        hashedToken,
        TokenType.PASSWORD_RESET,
      );

      if (tokenDoc) {
        // Invalidate the token after successful verification
        await this.tokenRepository.updateById(objectIdToString(tokenDoc._id), {
          isRevoked: true,
        });
        return true;
      }

      return false;
    } catch (error) {
      this.logger.error(
        `Failed to verify password reset token: ${getErrorMessage(error)}`,
      );
      return false;
    }
  }

  /**
   * Verify email verification token
   */
  async verifyEmailVerificationToken(token: string): Promise<boolean> {
    try {
      const hashedToken = this.hashToken(token);
      const tokenDoc = await this.tokenRepository.findValidToken(
        hashedToken,
        TokenType.EMAIL_VERIFICATION,
      );

      if (tokenDoc) {
        // Invalidate the token after successful verification
        await this.tokenRepository.updateById(objectIdToString(tokenDoc._id), {
          isRevoked: true,
        });
        return true;
      }

      return false;
    } catch (error) {
      this.logger.error(
        `Failed to verify email verification token: ${getErrorMessage(error)}`,
      );
      return false;
    }
  }

  /**
   * Invalidate a refresh token by its hash
   * @param token The hashed token to invalidate
   */
  async invalidateRefreshToken(token: string): Promise<void> {
    try {
      // The token passed here should already be hashed
      // If it's not hashed, hash it first
      const hashedToken = token.length === 64 ? token : this.hashToken(token);

      const result = await this.tokenRepository.revokeByToken(hashedToken);

      if (result) {
        this.logger.log(
          `Refresh token invalidated successfully: ${hashedToken.substring(0, 10)}...`,
        );
      } else {
        this.logger.warn(
          `Refresh token not found for invalidation: ${hashedToken.substring(0, 10)}...`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to invalidate refresh token: ${getErrorMessage(error)}`,
      );
      throw error; // Re-throw to handle in calling method
    }
  }

  /**
   * Invalidate all refresh tokens for a user
   */
  async invalidateAllRefreshTokens(userId: string): Promise<void> {
    try {
      const revokedCount = await this.tokenRepository.revokeAllByUserId(
        userId,
        TokenType.REFRESH,
      );

      this.logger.log(
        `${revokedCount} refresh tokens invalidated for user ${userId}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to invalidate all refresh tokens: ${getErrorMessage(error)}`,
      );
    }
  }

  /**
   * Count active refresh tokens for a user
   * Only counts non-revoked, non-expired tokens
   */
  async countActiveRefreshTokens(userId: string): Promise<number> {
    try {
      const count = await this.tokenRepository.countActiveTokens(
        userId,
        TokenType.REFRESH,
      );

      this.logger.debug(
        `Found ${count} active refresh tokens for user ${userId}`,
      );
      return count;
    } catch (error) {
      this.logger.error(
        `Failed to count active refresh tokens: ${getErrorMessage(error)}`,
      );
      return 0;
    }
  }

  /**
   * Get user sessions with device information
   * Only returns active (non-revoked) sessions
   */
  async getUserSessions(userId: string): Promise<SessionInfo[]> {
    try {
      const tokens = await this.tokenRepository.findActiveTokensByUserId(
        userId,
        TokenType.REFRESH,
      );

      // Filter out revoked tokens and map to session info
      const activeSessions = tokens
        .filter((token) => !token.isRevoked) // Ensure only active sessions
        .map((token) => ({
          id: objectIdToString(token._id),
          userId: objectIdToString(token.userId),
          tokenId: objectIdToString(token._id), // Using token ID as session ID for backward compatibility
          deviceInfo: token.deviceInfo
            ? (JSON.parse(token.deviceInfo) as DeviceInfo)
            : {
                deviceType: 'unknown' as const,
                browser: 'Unknown',
                os: 'Unknown',
                deviceId: 'unknown',
                isTrusted: false,
              },
          ipAddress: token.ipAddress || 'unknown',
          userAgent: token.userAgent || 'unknown',
          lastUsedAt: token.lastUsedAt || token.updatedAt,
          createdAt: token.createdAt,
          isActive: true, // All returned sessions are active
        }));

      this.logger.log(
        `Retrieved ${activeSessions.length} active sessions for user ${userId}`,
      );
      return activeSessions;
    } catch (error) {
      this.logger.error(
        `Failed to get user sessions: ${getErrorMessage(error)}`,
      );
      return [];
    }
  }

  /**
   * Get session by ID
   */
  async getSessionById(sessionId: string): Promise<TokenDocument | null> {
    try {
      return await this.tokenRepository.findById(sessionId);
    } catch (error) {
      this.logger.error(
        `Failed to get session by ID: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Get oldest session for a user
   */
  async getOldestSession(userId: string): Promise<TokenDocument | null> {
    try {
      return await this.tokenRepository.findOldestToken(
        userId,
        TokenType.REFRESH,
      );
    } catch (error) {
      this.logger.error(
        `Failed to get oldest session: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Update session last used timestamp
   */
  async updateSessionLastUsed(sessionId: string): Promise<void> {
    try {
      await this.tokenRepository.updateLastUsed(sessionId);
    } catch (error) {
      this.logger.error(
        `Failed to update session last used: ${getErrorMessage(error)}`,
      );
    }
  }

  /**
   * Clean up expired tokens
   */
  async cleanupExpiredTokens(): Promise<number> {
    try {
      return await this.tokenRepository.cleanupExpiredTokens();
    } catch (error) {
      this.logger.error(
        `Failed to cleanup expired tokens: ${getErrorMessage(error)}`,
      );
      return 0;
    }
  }

  /**
   * Clean up revoked tokens (optional maintenance)
   */
  async cleanupRevokedTokens(): Promise<number> {
    try {
      const result = await this.tokenRepository.cleanupRevokedTokens();
      this.logger.log(`Cleaned up ${result} revoked tokens`);
      return result;
    } catch (error) {
      this.logger.error(
        `Failed to cleanup revoked tokens: ${getErrorMessage(error)}`,
      );
      return 0;
    }
  }

  /**
   * Hash token for storage
   */
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  /**
   * Generate a secure random token
   */
  private generateSecureToken(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Generate random token
   */
  generateToken(): string {
    return randomBytes(32).toString('hex');
  }
}
