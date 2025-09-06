import { Injectable, Logger } from '@nestjs/common';
import { ITokenInvalidator } from '../interfaces/session-manager.interface';
import { TokenService } from '@tokens/services/token.service';

/**
 * Token Invalidator Service
 * Handles only token invalidation operations
 * Follows Single Responsibility Principle
 */
@Injectable()
export class TokenInvalidatorService implements ITokenInvalidator {
  private readonly logger = new Logger(TokenInvalidatorService.name);

  constructor(private readonly tokenService: TokenService) {}

  /**
   * Safe error message extraction
   */
  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    if (typeof error === 'string') {
      return error;
    }
    return 'Unknown error';
  }

  /**
   * Invalidate a specific token
   */
  async invalidateToken(tokenId: string): Promise<void> {
    try {
      await this.tokenService.invalidateRefreshToken(tokenId);
      this.logger.log(`Token ${tokenId} invalidated successfully`);
    } catch (error) {
      this.logger.error(
        `Failed to invalidate token ${tokenId}: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Invalidate all tokens for a user
   */
  async invalidateAllUserTokens(userId: string): Promise<void> {
    try {
      await this.tokenService.invalidateAllRefreshTokens(userId);
      this.logger.log(`All tokens invalidated for user ${userId}`);
    } catch (error) {
      this.logger.error(
        `Failed to invalidate all tokens for user ${userId}: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }
}
