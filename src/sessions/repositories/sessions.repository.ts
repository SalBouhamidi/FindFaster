import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Session, SessionDocument } from '../schemas/session.schema';

@Injectable()
export class SessionsRepository {
  private readonly logger = new Logger(SessionsRepository.name);

  constructor(
    @InjectModel(Session.name) private sessionModel: Model<SessionDocument>,
  ) {}

  /**
   * Create a new session
   */
  async create(sessionData: Partial<Session>): Promise<SessionDocument> {
    try {
      const session = new this.sessionModel(sessionData);
      const savedSession = await session.save();

      this.logger.log(
        `Session created for user ${sessionData.userId?.toString() || 'unknown'}`,
      );
      return savedSession;
    } catch (error) {
      this.logger.error(`Failed to create session: ${error}`);
      throw error;
    }
  }

  /**
   * Find active sessions for a user
   */
  async findActiveByUserId(userId: string): Promise<SessionDocument[]> {
    try {
      return await this.sessionModel
        .find({
          userId: new Types.ObjectId(userId),
          isActive: true,
        })
        .sort({ lastUsedAt: -1 })
        .exec();
    } catch (error) {
      this.logger.error(
        `Failed to find active sessions for user ${userId}: ${error}`,
      );
      return [];
    }
  }

  /**
   * Find session by ID
   */
  async findById(sessionId: string): Promise<SessionDocument | null> {
    try {
      return await this.sessionModel.findById(sessionId).exec();
    } catch (error) {
      this.logger.error(`Failed to find session ${sessionId}: ${error}`);
      return null;
    }
  }

  /**
   * Find session by token ID
   */
  async findByTokenId(tokenId: string): Promise<SessionDocument | null> {
    try {
      return await this.sessionModel
        .findOne({ tokenId: new Types.ObjectId(tokenId) })
        .exec();
    } catch (error) {
      this.logger.error(`Failed to find session by token ${tokenId}: ${error}`);
      return null;
    }
  }

  /**
   * Update session last used timestamp
   */
  async updateLastUsed(sessionId: string): Promise<void> {
    try {
      await this.sessionModel
        .findByIdAndUpdate(sessionId, { lastUsedAt: new Date() })
        .exec();
    } catch (error) {
      this.logger.error(
        `Failed to update last used for session ${sessionId}: ${error}`,
      );
    }
  }

  /**
   * Deactivate a session
   */
  async deactivate(sessionId: string): Promise<void> {
    try {
      await this.sessionModel
        .findByIdAndUpdate(sessionId, { isActive: false })
        .exec();

      this.logger.log(`Session ${sessionId} deactivated`);
    } catch (error) {
      this.logger.error(`Failed to deactivate session ${sessionId}: ${error}`);
    }
  }

  /**
   * Deactivate all sessions for a user
   */
  async deactivateAllByUserId(userId: string): Promise<number> {
    try {
      const result = await this.sessionModel
        .updateMany(
          { userId: new Types.ObjectId(userId), isActive: true },
          { isActive: false },
        )
        .exec();

      this.logger.log(
        `${result.modifiedCount} sessions deactivated for user ${userId}`,
      );
      return result.modifiedCount || 0;
    } catch (error) {
      this.logger.error(
        `Failed to deactivate sessions for user ${userId}: ${error}`,
      );
      return 0;
    }
  }

  /**
   * Deactivate all sessions except the current one
   */
  async deactivateOthersByUserId(
    userId: string,
    currentSessionId: string,
  ): Promise<number> {
    try {
      const result = await this.sessionModel
        .updateMany(
          {
            userId: new Types.ObjectId(userId),
            isActive: true,
            _id: { $ne: currentSessionId },
          },
          { isActive: false },
        )
        .exec();

      this.logger.log(
        `${result.modifiedCount} other sessions deactivated for user ${userId}`,
      );
      return result.modifiedCount || 0;
    } catch (error) {
      this.logger.error(
        `Failed to deactivate other sessions for user ${userId}: ${error}`,
      );
      return 0;
    }
  }

  /**
   * Find session by device ID for a user
   */
  async findByDeviceId(
    userId: string,
    deviceId: string,
  ): Promise<SessionDocument | null> {
    try {
      return await this.sessionModel
        .findOne({
          userId: new Types.ObjectId(userId),
          'deviceInfo.deviceId': deviceId,
          isActive: true,
        })
        .exec();
    } catch (error) {
      this.logger.error(
        `Failed to find session by device ${deviceId} for user ${userId}: ${error}`,
      );
      return null;
    }
  }

  /**
   * Count active sessions for a user
   */
  async countActiveByUserId(userId: string): Promise<number> {
    try {
      return await this.sessionModel
        .countDocuments({
          userId: new Types.ObjectId(userId),
          isActive: true,
        })
        .exec();
    } catch (error) {
      this.logger.error(
        `Failed to count active sessions for user ${userId}: ${error}`,
      );
      return 0;
    }
  }

  /**
   * Get oldest active session for a user
   */
  async findOldestActiveByUserId(
    userId: string,
  ): Promise<SessionDocument | null> {
    try {
      return await this.sessionModel
        .findOne({
          userId: new Types.ObjectId(userId),
          isActive: true,
        })
        .sort({ createdAt: 1 })
        .exec();
    } catch (error) {
      this.logger.error(
        `Failed to find oldest session for user ${userId}: ${error}`,
      );
      return null;
    }
  }

  /**
   * Clean up old inactive sessions
   */
  async cleanupOldSessions(daysOld: number = 30): Promise<number> {
    try {
      const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);

      const result = await this.sessionModel
        .deleteMany({
          isActive: false,
          updatedAt: { $lt: cutoffDate },
        })
        .exec();

      if (result.deletedCount && result.deletedCount > 0) {
        this.logger.log(
          `Cleaned up ${result.deletedCount} old inactive sessions`,
        );
      }

      return result.deletedCount || 0;
    } catch (error) {
      this.logger.error(`Failed to cleanup old sessions: ${error}`);
      return 0;
    }
  }

  /**
   * Get session statistics for a user
   */
  async getSessionStats(userId: string): Promise<{
    totalSessions: number;
    activeSessions: number;
    deviceTypes: Record<string, number>;
    avgSessionDuration: number;
  }> {
    try {
      const sessions = await this.findActiveByUserId(userId);

      const deviceTypes = sessions.reduce(
        (acc, session) => {
          const type = session.deviceInfo.deviceType;
          acc[type] = (acc[type] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      );

      const avgDuration =
        sessions.length > 0
          ? sessions.reduce(
              (sum, session) =>
                sum +
                (session.lastUsedAt.getTime() - session.createdAt.getTime()),
              0,
            ) / sessions.length
          : 0;

      return {
        totalSessions: sessions.length,
        activeSessions: sessions.filter((s) => s.isActive).length,
        deviceTypes,
        avgSessionDuration: avgDuration,
      };
    } catch (error) {
      this.logger.error(
        `Failed to get session stats for user ${userId}: ${error}`,
      );
      return {
        totalSessions: 0,
        activeSessions: 0,
        deviceTypes: {},
        avgSessionDuration: 0,
      };
    }
  }
}
