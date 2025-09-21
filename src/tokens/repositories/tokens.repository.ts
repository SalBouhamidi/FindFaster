import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Token, TokenDocument, TokenType } from '../schemas/token.schema';
import { ITokenRepository } from '../interfaces/token-repository.interface';

/**
 * Token Repository Implementation
 * Handles all database operations for tokens
 */
@Injectable()
export class TokenRepository implements ITokenRepository {
  private readonly logger = new Logger(TokenRepository.name);

  constructor(
    @InjectModel(Token.name) private readonly tokenModel: Model<TokenDocument>,
  ) {}

  /**
   * Create a new token
   */
  async create(
    tokenData: Omit<Token, 'createdAt' | 'updatedAt' | 'userId'> & {
      userId: string;
    },
  ): Promise<TokenDocument> {
    try {
      const tokenDataWithObjectId = {
        ...tokenData,
        userId: new Types.ObjectId(tokenData.userId),
      };
      const token = new this.tokenModel(tokenDataWithObjectId);
      const savedToken = await token.save();

      this.logger.log(
        `Token created: ${savedToken.type} for user ${savedToken.userId.toString()}`,
      );
      return savedToken;
    } catch (error) {
      this.logger.error(`Failed to create token: ${error}`);
      throw error;
    }
  }

  /**
   * Find token by token value and optionally by type
   */
  async findByToken(
    token: string,
    type?: TokenType,
  ): Promise<TokenDocument | null> {
    try {
      const filter: { token: string; type?: TokenType } = { token };
      if (type) {
        filter.type = type;
      }

      return await this.tokenModel.findOne(filter).exec();
    } catch (error) {
      this.logger.error(`Failed to find token: ${error}`);
      return null;
    }
  }

  /**
   * Find all tokens by user ID, optionally filtered by type
   */
  async findByUserId(
    userId: string,
    type?: TokenType,
  ): Promise<TokenDocument[]> {
    try {
      const filter: { userId: Types.ObjectId; type?: TokenType } = {
        userId: new Types.ObjectId(userId),
      };
      if (type) {
        filter.type = type;
      }

      return await this.tokenModel.find(filter).sort({ createdAt: -1 }).exec();
    } catch (error) {
      this.logger.error(`Failed to find tokens by user ID: ${error}`);
      return [];
    }
  }

  /**
   * Find tokens by user ID and specific type
   */
  async findByUserIdAndType(
    userId: string,
    type: TokenType,
  ): Promise<TokenDocument[]> {
    return this.findByUserId(userId, type);
  }

  /**
   * Update token by ID
   */
  async updateById(
    tokenId: string,
    updateData: Partial<Token>,
  ): Promise<TokenDocument | null> {
    try {
      const updatedToken = await this.tokenModel
        .findByIdAndUpdate(tokenId, updateData, { new: true })
        .exec();

      if (updatedToken) {
        this.logger.log(`Token updated: ${tokenId}`);
      }

      return updatedToken;
    } catch (error) {
      this.logger.error(`Failed to update token: ${error}`);
      return null;
    }
  }

  /**
   * Delete token by ID
   */
  async deleteById(tokenId: string): Promise<boolean> {
    try {
      const result = await this.tokenModel.findByIdAndDelete(tokenId).exec();

      if (result) {
        this.logger.log(`Token deleted: ${tokenId}`);
        return true;
      }

      return false;
    } catch (error) {
      this.logger.error(`Failed to delete token: ${error}`);
      return false;
    }
  }

  /**
   * Delete all tokens by user ID, optionally filtered by type
   */
  async deleteByUserId(userId: string, type?: TokenType): Promise<number> {
    try {
      const filter: { userId: Types.ObjectId; type?: TokenType } = {
        userId: new Types.ObjectId(userId),
      };
      if (type) {
        filter.type = type;
      }

      const result = await this.tokenModel.deleteMany(filter).exec();

      this.logger.log(
        `Deleted ${result.deletedCount} tokens for user ${userId}`,
      );
      return result.deletedCount || 0;
    } catch (error) {
      this.logger.error(`Failed to delete tokens by user ID: ${error}`);
      return 0;
    }
  }

  /**
   * Revoke a token by marking it as revoked
   */
  async revokeByToken(token: string): Promise<TokenDocument | null> {
    try {
      const revokedToken = await this.tokenModel
        .findOneAndUpdate({ token }, { isRevoked: true }, { new: true })
        .exec();

      if (revokedToken) {
        this.logger.log(`Token revoked: ${token.substring(0, 10)}...`);
      }

      return revokedToken;
    } catch (error) {
      this.logger.error(`Failed to revoke token: ${error}`);
      return null;
    }
  }

  /**
   * Revoke all tokens for a user, optionally filtered by type
   */
  async revokeAllByUserId(userId: string, type?: TokenType): Promise<number> {
    try {
      const filter: {
        userId: Types.ObjectId;
        isRevoked: boolean;
        type?: TokenType;
      } = {
        userId: new Types.ObjectId(userId),
        isRevoked: false,
      };
      if (type) {
        filter.type = type;
      }

      const result = await this.tokenModel
        .updateMany(filter, { isRevoked: true })
        .exec();

      this.logger.log(
        `Revoked ${result.modifiedCount} tokens for user ${userId}`,
      );
      return result.modifiedCount || 0;
    } catch (error) {
      this.logger.error(`Failed to revoke tokens: ${error}`);
      return 0;
    }
  }

  /**
   * Find a valid (non-revoked, non-expired) token
   */
  async findValidToken(
    token: string,
    type: TokenType,
  ): Promise<TokenDocument | null> {
    try {
      return await this.tokenModel
        .findOne({
          token,
          type,
          isRevoked: false,
          expiresAt: { $gte: new Date() },
        })
        .exec();
    } catch (error) {
      this.logger.error(`Failed to find valid token: ${error}`);
      return null;
    }
  }

  /**
   * Delete all expired tokens (cleanup)
   */
  async deleteExpiredTokens(): Promise<number> {
    try {
      const result = await this.tokenModel
        .deleteMany({
          expiresAt: { $lt: new Date() },
        })
        .exec();

      if (result.deletedCount && result.deletedCount > 0) {
        this.logger.log(`Cleaned up ${result.deletedCount} expired tokens`);
      }

      return result.deletedCount || 0;
    } catch (error) {
      this.logger.error(`Failed to delete expired tokens: ${error}`);
      return 0;
    }
  }

  /**
   * Count tokens by user ID, optionally filtered by type
   */
  async countByUserId(userId: string, type?: TokenType): Promise<number> {
    try {
      const filter: {
        userId: Types.ObjectId;
        isRevoked: boolean;
        expiresAt: { $gte: Date };
        type?: TokenType;
      } = {
        userId: new Types.ObjectId(userId),
        isRevoked: false,
        expiresAt: { $gte: new Date() },
      };
      if (type) {
        filter.type = type;
      }

      return await this.tokenModel.countDocuments(filter).exec();
    } catch (error) {
      this.logger.error(`Failed to count tokens: ${error}`);
      return 0;
    }
  }

  /**
   * Count active tokens by user ID and type
   */
  async countActiveTokens(userId: string, type: TokenType): Promise<number> {
    try {
      const filter: {
        userId: Types.ObjectId;
        type: TokenType;
        isRevoked: boolean;
        expiresAt: { $gte: Date };
      } = {
        userId: new Types.ObjectId(userId),
        type,
        isRevoked: false,
        expiresAt: { $gte: new Date() },
      };

      return await this.tokenModel.countDocuments(filter).exec();
    } catch (error) {
      this.logger.error(`Failed to count active tokens: ${error}`);
      return 0;
    }
  }

  /**
   * Find active tokens by user ID and type
   */
  async findActiveTokensByUserId(
    userId: string,
    type: TokenType,
  ): Promise<TokenDocument[]> {
    try {
      const filter: {
        userId: Types.ObjectId;
        type: TokenType;
        isRevoked: boolean;
        expiresAt: { $gte: Date };
      } = {
        userId: new Types.ObjectId(userId),
        type,
        isRevoked: false,
        expiresAt: { $gte: new Date() },
      };

      return await this.tokenModel.find(filter).sort({ createdAt: -1 }).exec();
    } catch (error) {
      this.logger.error(`Failed to find active tokens: ${error}`);
      return [];
    }
  }

  /**
   * Find token by ID
   */
  async findById(tokenId: string): Promise<TokenDocument | null> {
    try {
      return await this.tokenModel.findById(tokenId).exec();
    } catch (error) {
      this.logger.error(`Failed to find token by ID: ${error}`);
      return null;
    }
  }

  /**
   * Find oldest token by user ID and type
   */
  async findOldestToken(
    userId: string,
    type: TokenType,
  ): Promise<TokenDocument | null> {
    try {
      const filter: {
        userId: Types.ObjectId;
        type: TokenType;
        isRevoked: boolean;
        expiresAt: { $gte: Date };
      } = {
        userId: new Types.ObjectId(userId),
        type,
        isRevoked: false,
        expiresAt: { $gte: new Date() },
      };

      return await this.tokenModel
        .findOne(filter)
        .sort({ createdAt: 1 })
        .exec();
    } catch (error) {
      this.logger.error(`Failed to find oldest token: ${error}`);
      return null;
    }
  }

  /**
   * Update token last used timestamp
   */
  async updateLastUsed(tokenId: string): Promise<void> {
    try {
      await this.tokenModel
        .findByIdAndUpdate(tokenId, { lastUsedAt: new Date() })
        .exec();
    } catch (error) {
      this.logger.error(`Failed to update token last used: ${error}`);
    }
  }

  /**
   * Clean up expired tokens
   */
  async cleanupExpiredTokens(): Promise<number> {
    try {
      const result = await this.tokenModel
        .deleteMany({
          expiresAt: { $lt: new Date() },
        })
        .exec();

      if (result.deletedCount && result.deletedCount > 0) {
        this.logger.log(`Cleaned up ${result.deletedCount} expired tokens`);
      }

      return result.deletedCount || 0;
    } catch (error) {
      this.logger.error(`Failed to cleanup expired tokens: ${error}`);
      return 0;
    }
  }

  /**
   * Clean up revoked tokens (optional maintenance)
   */
  async cleanupRevokedTokens(): Promise<number> {
    try {
      const result = await this.tokenModel
        .deleteMany({
          isRevoked: true,
          // Only delete revoked tokens older than 24 hours
          updatedAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        })
        .exec();

      if (result.deletedCount && result.deletedCount > 0) {
        this.logger.log(`Cleaned up ${result.deletedCount} revoked tokens`);
      }

      return result.deletedCount || 0;
    } catch (error) {
      this.logger.error(`Failed to cleanup revoked tokens: ${error}`);
      return 0;
    }
  }
}
