import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  UseGuards,
  Req,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiParam,
  ApiOkResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Request } from 'express';
import { JwtAuthGuard } from '@auth/guards/jwt-auth.guard';
import { GetUser } from '@common/decorators/get-user.decorator';
import { AuthenticatedUser } from '@auth/interfaces/auth.interface';
import { SessionCoordinatorService } from '@sessions/services/session-coordinator.service';
import { SessionExtractorService } from '@sessions/services/session-extractor.service';
import {
  SessionStats,
  SessionStatsSummary,
} from '@sessions/interfaces/session-manager.interface';

/**
 * Sessions controller
 * Handles all session-related HTTP requests
 * Separated from AuthController to respect PSR (Principle of Separation of Responsibilities)
 */
@ApiTags('Sessions')
@ApiBearerAuth('JWT-auth')
@Controller('sessions')
export class SessionsController {
  private readonly logger = new Logger(SessionsController.name);

  constructor(
    private readonly sessionCoordinator: SessionCoordinatorService,
    private readonly sessionExtractor: SessionExtractorService,
  ) {}

  /**
   * Get user sessions
   * Returns all active sessions for the authenticated user
   * @param user Authenticated user
   */
  @Get()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get user sessions' })
  @ApiOkResponse({
    description: 'User sessions',
    schema: {
      example: {
        sessions: [
          {
            id: 'session_id',
            deviceInfo: {
              deviceType: 'desktop',
              browser: 'Chrome',
              os: 'Windows',
              deviceId: 'device_hash',
              isTrusted: true,
            },
            ipAddress: '192.168.1.1',
            userAgent: 'Mozilla/5.0...',
            lastUsedAt: '2025-08-16T13:40:00.000Z',
            createdAt: '2025-08-16T13:00:00.000Z',
            isActive: true,
          },
        ],
        totalSessions: 1,
        maxAllowedSessions: 3,
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async getUserSessions(
    @GetUser() user: AuthenticatedUser,
  ): Promise<SessionStats> {
    this.logger.log(`Fetching sessions for user ${user.id}`);
    return await this.sessionCoordinator.getUserSessions(user.id);
  }

  /**
   * Revoke specific session
   * @param user Authenticated user
   * @param sessionId Session ID to revoke
   */
  @Delete(':sessionId')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Revoke specific session' })
  @ApiParam({ name: 'sessionId', description: 'Session ID to revoke' })
  @ApiOkResponse({
    description: 'Session revoked successfully',
    schema: {
      example: { message: 'Session revoked successfully' },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async revokeSession(
    @GetUser() user: AuthenticatedUser,
    @Param('sessionId') sessionId: string,
  ) {
    this.logger.log(`Revoking session ${sessionId} for user ${user.id}`);
    await this.sessionCoordinator.revokeSession(user.id, sessionId);
    return { message: 'Session revoked successfully' };
  }

  /**
   * Revoke all other sessions
   * Keeps current session active, revokes all others
   * @param user Authenticated user
   * @param req Express request
   */
  @Post('revoke-others')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Revoke all other sessions' })
  @ApiOkResponse({
    description: 'All other sessions revoked successfully',
    schema: {
      example: { message: 'All other sessions revoked successfully' },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async revokeOtherSessions(
    @GetUser() user: AuthenticatedUser,
    @Req() req: Request,
  ) {
    this.logger.log(`Revoking other sessions for user ${user.id}`);

    // Get current session ID from refresh token
    const refreshToken = req.cookies?.refresh_token as string;
    if (refreshToken) {
      // Extract current session ID from JWT token
      const currentSessionId =
        this.sessionExtractor.extractCurrentSessionId(req);

      if (!currentSessionId) {
        throw new BadRequestException('Unable to identify current session');
      }

      await this.sessionCoordinator.revokeOtherSessions(
        user.id,
        currentSessionId,
      );
    }
    return { message: 'All other sessions revoked successfully' };
  }

  /**
   * Get session statistics
   * Returns session count and limits for the user
   * @param user Authenticated user
   */
  @Get('stats')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get session statistics' })
  @ApiOkResponse({
    description: 'Session statistics',
    schema: {
      example: {
        activeSessions: 2,
        maxAllowedSessions: 3,
        sessionLimitReached: false,
        lastSessionCreated: '2025-08-16T13:00:00.000Z',
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  async getSessionStats(
    @GetUser() user: AuthenticatedUser,
  ): Promise<SessionStatsSummary> {
    this.logger.log(`Fetching session stats for user ${user.id}`);
    const sessions = await this.sessionCoordinator.getUserSessions(user.id);

    return {
      activeSessions: sessions.totalSessions,
      maxAllowedSessions: sessions.maxAllowedSessions,
      sessionLimitReached:
        sessions.totalSessions >= sessions.maxAllowedSessions,
      lastSessionCreated:
        sessions.sessions.length > 0
          ? Math.max(
              ...sessions.sessions.map((s) => new Date(s.createdAt).getTime()),
            )
          : null,
    };
  }
}
