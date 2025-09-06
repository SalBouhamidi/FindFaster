import { Token, TokenDocument, TokenType } from '@/tokens/schemas/token.schema';

/**
 * Token Repository Interface
 * Defines the contract for token data operations
 */
export interface ITokenRepository {
  /**
   * Create a new token
   */
  create(
    tokenData: Omit<Token, 'createdAt' | 'updatedAt' | 'userId'> & {
      userId: string;
    },
  ): Promise<TokenDocument>;

  /**
   * Find token by token value and optionally by type
   */
  findByToken(token: string, type?: TokenType): Promise<TokenDocument | null>;

  /**
   * Find all tokens by user ID, optionally filtered by type
   */
  findByUserId(userId: string, type?: TokenType): Promise<TokenDocument[]>;

  /**
   * Find tokens by user ID and specific type
   */
  findByUserIdAndType(
    userId: string,
    type: TokenType,
  ): Promise<TokenDocument[]>;

  /**
   * Update token by ID
   */
  updateById(
    tokenId: string,
    updateData: Partial<Token>,
  ): Promise<TokenDocument | null>;

  /**
   * Delete token by ID
   */
  deleteById(tokenId: string): Promise<boolean>;

  /**
   * Delete all tokens by user ID, optionally filtered by type
   */
  deleteByUserId(userId: string, type?: TokenType): Promise<number>;

  /**
   * Revoke a token by marking it as revoked
   */
  revokeByToken(token: string): Promise<TokenDocument | null>;

  /**
   * Revoke all tokens for a user, optionally filtered by type
   */
  revokeAllByUserId(userId: string, type?: TokenType): Promise<number>;

  /**
   * Find a valid (non-revoked, non-expired) token
   */
  findValidToken(token: string, type: TokenType): Promise<TokenDocument | null>;

  /**
   * Delete all expired tokens (cleanup)
   */
  deleteExpiredTokens(): Promise<number>;

  /**
   * Count tokens by user ID, optionally filtered by type
   */
  countByUserId(userId: string, type?: TokenType): Promise<number>;
}
