import { Request } from 'express';

/**
 * Device information interface
 */
export interface DeviceInfo {
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  browser: string;
  os: string;
  deviceId: string;
  isTrusted: boolean;
}

/**
 * Session data interface
 */
export interface SessionData {
  _id: string;
  userId: string;
  tokenId: string;
  deviceInfo: DeviceInfo;
  ipAddress: string;
  userAgent: string;
  lastUsedAt: Date;
  createdAt: Date;
  isActive: boolean;
  duration?: number;
}

/**
 * Session statistics interface
 */
export interface SessionStats {
  sessions: SessionData[];
  totalSessions: number;
  maxAllowedSessions: number;
  statistics: {
    deviceTypes: Record<string, number>;
    avgSessionDuration: number;
    totalActiveTime: number;
  };
}

/**
 * Session statistics summary interface
 */
export interface SessionStatsSummary {
  activeSessions: number;
  maxAllowedSessions: number;
  sessionLimitReached: boolean;
  lastSessionCreated: number | null;
}

/**
 * Interface for session management operations
 * Follows Dependency Inversion Principle
 */
export interface ISessionManager {
  /**
   * Create a new session
   */
  createSession(
    userId: string,
    tokenId: string,
    deviceInfo: DeviceInfo,
    request: Request,
  ): Promise<void>;

  /**
   * Get user sessions
   */
  getUserSessions(userId: string): Promise<SessionStats>;

  /**
   * Revoke a specific session
   */
  revokeSession(userId: string, sessionId: string): Promise<void>;

  /**
   * Revoke all other sessions except current
   */
  revokeOtherSessions(userId: string, currentSessionId: string): Promise<void>;

  /**
   * Enforce session limit
   */
  enforceSessionLimit(userId: string): Promise<void>;

  /**
   * Get session statistics
   */
  getSessionStats(userId: string): Promise<SessionStatsSummary>;

  /**
   * Generate device information from request
   */
  generateDeviceInfo(req: Request): DeviceInfo;
}

/**
 * Interface for token invalidation
 * Separates token concerns from session management
 */
export interface ITokenInvalidator {
  /**
   * Invalidate a specific token
   */
  invalidateToken(tokenId: string): Promise<void>;

  /**
   * Invalidate all tokens for a user
   */
  invalidateAllUserTokens(userId: string): Promise<void>;
}

/**
 * Interface for session repository operations
 */
export interface ISessionRepository {
  /**
   * Find session by ID
   */
  findById(sessionId: string): Promise<SessionData | null>;

  /**
   * Find active sessions by user ID
   */
  findActiveByUserId(userId: string): Promise<SessionData[]>;

  /**
   * Find session by device ID
   */
  findByDeviceId(userId: string, deviceId: string): Promise<SessionData | null>;

  /**
   * Count active sessions by user ID
   */
  countActiveByUserId(userId: string): Promise<number>;

  /**
   * Deactivate a session
   */
  deactivate(sessionId: string): Promise<void>;

  /**
   * Create a new session
   */
  create(
    sessionData: Omit<SessionData, '_id' | 'createdAt'>,
  ): Promise<SessionData>;
}
