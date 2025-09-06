import { Injectable, Logger } from '@nestjs/common';
import { Request } from 'express';
import { UAParser } from 'ua-parser-js';
import { createHash } from 'crypto';
import {
  ISessionManager,
  DeviceInfo,
  SessionStats,
  SessionStatsSummary,
} from '../interfaces/session-manager.interface';
import { SESSIONS_CONFIG } from '../../config/sessions.config';
import { SessionsRepository } from '../repositories/sessions.repository';
import { TokenInvalidatorService } from './token-invalidator.service';
import { Types } from 'mongoose';

/**
 * Session Coordinator Service
 * Acts as a facade to coordinate between sessions and tokens
 * Follows Single Responsibility Principle
 */
@Injectable()
export class SessionCoordinatorService implements ISessionManager {
  private readonly logger = new Logger(SessionCoordinatorService.name);

  constructor(
    private readonly sessionRepository: SessionsRepository,
    private readonly tokenInvalidator: TokenInvalidatorService,
  ) {}

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
   * Create a new session with rotation logic
   * If a session already exists for the same device, it will be replaced
   */
  async createSession(
    userId: string,
    tokenId: string,
    deviceInfo: DeviceInfo,
    request: Request,
  ): Promise<void> {
    try {
      // Check if a session already exists for this device
      const existingSession = await this.sessionRepository.findByDeviceId(
        userId,
        deviceInfo.deviceId,
      );

      if (existingSession) {
        this.logger.log(
          `Replacing existing session for device ${deviceInfo.deviceId} on user ${userId}`,
        );

        // Invalidate the old session's token
        await this.tokenInvalidator.invalidateToken(
          existingSession.tokenId.toString(),
        );

        // Deactivate the old session
        await this.sessionRepository.deactivate(
          (existingSession._id as Types.ObjectId).toString(),
        );

        this.logger.log(
          `Old session ${(existingSession._id as Types.ObjectId).toString()} deactivated for device ${deviceInfo.deviceId}`,
        );
      }

      // Create the new session
      await this.sessionRepository.create({
        userId: new Types.ObjectId(userId),
        tokenId: new Types.ObjectId(tokenId),
        deviceInfo,
        ipAddress: this.getClientIP(request),
        userAgent: request.headers['user-agent'] || 'unknown',
        lastUsedAt: new Date(),
        isActive: true,
      });

      this.logger.log(
        `Session ${existingSession ? 'replaced' : 'created'} for user ${userId} on ${deviceInfo.deviceType} device (${deviceInfo.deviceId})`,
      );
    } catch (error: unknown) {
      this.logger.error(
        `Failed to create session: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Get user sessions
   */
  async getUserSessions(userId: string): Promise<SessionStats> {
    try {
      const sessions = await this.sessionRepository.findActiveByUserId(userId);
      const totalSessions = sessions.length;
      const maxAllowedSessions = 3; // Should come from config

      // Calculate statistics
      const deviceTypes = sessions.reduce<Record<string, number>>(
        (acc, session) => {
          const type = session.deviceInfo?.deviceType || 'unknown';
          acc[type] = (acc[type] || 0) + 1;
          return acc;
        },
        {},
      );

      // Calculate session duration based on creation time
      const now = new Date();
      const avgSessionDuration =
        sessions.length > 0
          ? sessions.reduce(
              (sum, session) =>
                sum + (now.getTime() - session.createdAt.getTime()),
              0,
            ) / sessions.length
          : 0;

      return {
        sessions: sessions.map((session) => ({
          _id: (session._id as Types.ObjectId).toString(),
          userId: session.userId.toString(),
          tokenId: session.tokenId.toString(),
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          lastUsedAt: session.lastUsedAt,
          createdAt: session.createdAt,
          isActive: session.isActive,
        })),
        totalSessions,
        maxAllowedSessions,
        statistics: {
          deviceTypes,
          avgSessionDuration,
          totalActiveTime: sessions.reduce(
            (sum, session) =>
              sum + (now.getTime() - session.createdAt.getTime()),
            0,
          ),
        },
      };
    } catch (error: unknown) {
      const errorMessage = this.getErrorMessage(error);
      this.logger.error(`Failed to get user sessions: ${errorMessage}`);
      throw error;
    }
  }

  /**
   * Revoke a specific session
   */
  async revokeSession(userId: string, sessionId: string): Promise<void> {
    try {
      // 1. Get session from session repository (correct source)
      const session = await this.sessionRepository.findById(sessionId);

      if (!session || session.userId.toString() !== userId) {
        throw new Error('Session not found or access denied');
      }

      // 2. Invalidate the corresponding token
      await this.tokenInvalidator.invalidateToken(session.tokenId.toString());

      // 3. Deactivate the session
      await this.sessionRepository.deactivate(sessionId);

      this.logger.log(`Session ${sessionId} revoked for user ${userId}`);
    } catch (error: unknown) {
      this.logger.error(
        `Failed to revoke session: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Revoke all other sessions except current
   */
  async revokeOtherSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<void> {
    try {
      // 1. Get all active sessions from session repository
      const sessions = await this.sessionRepository.findActiveByUserId(userId);

      let revokedCount = 0;

      for (const session of sessions) {
        if ((session._id as Types.ObjectId).toString() !== currentSessionId) {
          try {
            // 2. Invalidate the token
            await this.tokenInvalidator.invalidateToken(
              session.tokenId.toString(),
            );

            // 3. Deactivate the session
            await this.sessionRepository.deactivate(
              (session._id as Types.ObjectId).toString(),
            );

            revokedCount++;
          } catch (error: unknown) {
            const sessionId = (session._id as Types.ObjectId).toString();
            this.logger.error(
              `Failed to revoke session ${sessionId}: ${this.getErrorMessage(error)}`,
            );
          }
        }
      }

      this.logger.log(
        `Revoked ${revokedCount} other sessions for user ${userId}`,
      );
    } catch (error: unknown) {
      this.logger.error(
        `Failed to revoke other sessions: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Enforce session limit
   */
  async enforceSessionLimit(userId: string): Promise<void> {
    try {
      const activeSessions =
        await this.sessionRepository.countActiveByUserId(userId);
      const maxSessions = 3; // Should come from config

      if (activeSessions > maxSessions) {
        const sessionsToRevoke = activeSessions - maxSessions;

        this.logger.log(
          `Enforcing session limit: revoking ${sessionsToRevoke} oldest sessions for user ${userId}`,
        );

        // Get oldest sessions to revoke
        const sessions =
          await this.sessionRepository.findActiveByUserId(userId);
        const sortedSessions = sessions.sort(
          (a, b) =>
            new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
        );

        // Revoke the oldest sessions
        let revokedCount = 0;
        for (
          let i = 0;
          i < sessionsToRevoke && i < sortedSessions.length;
          i++
        ) {
          const session = sortedSessions[i];
          try {
            // Invalidate token
            await this.tokenInvalidator.invalidateToken(
              session.tokenId.toString(),
            );

            // Deactivate session
            await this.sessionRepository.deactivate(
              (session._id as Types.ObjectId).toString(),
            );

            revokedCount++;
          } catch (error: unknown) {
            const sessionId = (session._id as Types.ObjectId).toString();
            this.logger.error(
              `Failed to revoke session ${sessionId}: ${this.getErrorMessage(error)}`,
            );
          }
        }

        this.logger.log(
          `Successfully enforced session limit: revoked ${revokedCount}/${sessionsToRevoke} oldest sessions for user ${userId}`,
        );
      }
    } catch (error: unknown) {
      this.logger.error(
        `Failed to enforce session limit: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Get session statistics
   */
  async getSessionStats(userId: string): Promise<SessionStatsSummary> {
    try {
      const sessions = await this.getUserSessions(userId);

      return {
        activeSessions: sessions.totalSessions,
        maxAllowedSessions: sessions.maxAllowedSessions,
        sessionLimitReached:
          sessions.totalSessions >= sessions.maxAllowedSessions,
        lastSessionCreated:
          sessions.sessions.length > 0
            ? Math.max(
                ...sessions.sessions.map((s) =>
                  new Date(s.createdAt).getTime(),
                ),
              )
            : null,
      };
    } catch (error: unknown) {
      this.logger.error(
        `Failed to get session stats: ${this.getErrorMessage(error)}`,
      );
      throw error;
    }
  }

  /**
   * Generate device information from request
   */
  generateDeviceInfo(req: Request): DeviceInfo {
    const userAgent = req.headers['user-agent'] || '';
    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    // Determine device type
    let deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown' = 'unknown';
    if (result.device.type === 'mobile') deviceType = 'mobile';
    else if (result.device.type === 'tablet') deviceType = 'tablet';
    else if (result.os.name && !result.device.type) deviceType = 'desktop';

    // Generate unique device ID
    const deviceId = this.generateDeviceId(req);

    return {
      deviceType,
      browser: result.browser.name || 'Unknown',
      os: result.os.name || 'Unknown',
      deviceId,
      isTrusted: this.isTrustedDevice(req),
    };
  }

  /**
   * Generate unique device identifier
   */
  private generateDeviceId(req: Request): string {
    const components = [
      req.headers['user-agent'] || '',
      req.ip || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
    ];

    const combined = components.join('|');
    const hash = createHash('sha256').update(combined).digest('hex');
    return hash.substring(0, 16);
  }

  /**
   * Check if device is trusted
   */
  private isTrustedDevice(req: Request): boolean {
    const clientIP = this.getClientIP(req);

    return (
      (SESSIONS_CONFIG.DEVICE_TRUST_IPS as readonly string[]).includes(
        clientIP,
      ) ||
      (SESSIONS_CONFIG.DEVICE_TRUST_PREFIXES as readonly string[]).some(
        (prefix) => clientIP.startsWith(prefix),
      )
    );
  }

  /**
   * Get client IP address
   */
  private getClientIP(request: Request): string {
    const headers = request.headers;

    // Type-safe access to Express-specific properties
    const expressRequest = request as Request & {
      connection?: { remoteAddress?: string };
      socket?: { remoteAddress?: string };
    };

    return (
      (headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (headers['x-real-ip'] as string) ||
      expressRequest.connection?.remoteAddress ||
      expressRequest.socket?.remoteAddress ||
      'unknown'
    );
  }
}
