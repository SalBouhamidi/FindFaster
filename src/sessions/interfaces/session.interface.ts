/**
 * Interface for device information (matches the schema)
 */
export interface DeviceInfo {
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  browser: string;
  os: string;
  deviceId: string;
  isTrusted: boolean;
  browserVersion?: string;
  osVersion?: string;
  screenResolution?: string;
  timezone?: string;
}

/**
 * Interface for session information (matches the schema)
 */
export interface SessionInfo {
  id: string;
  userId: string;
  tokenId: string;
  deviceInfo: DeviceInfo;
  ipAddress: string;
  userAgent: string;
  lastUsedAt: Date;
  createdAt: Date;
  isActive: boolean;
  location?: {
    country?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
  securityInfo?: {
    isSuspicious: boolean;
    riskScore: number;
    flags: string[];
  };
  metadata?: {
    appVersion?: string;
    platform?: string;
    language?: string;
    referrer?: string;
  };
  // Virtual fields
  duration?: number;
  age?: number;
}

/**
 * Interface for session management response
 */
export interface SessionManagementResponse {
  sessions: SessionInfo[];
  totalSessions: number;
  maxAllowedSessions: number;
  statistics: {
    deviceTypes: Record<string, number>;
    avgSessionDuration: number;
    totalActiveTime: number;
  };
}

/**
 * Interface for session creation
 */
export interface CreateSessionDto {
  userId: string;
  tokenId: string;
  deviceInfo: DeviceInfo;
  ipAddress: string;
  userAgent: string;
  location?: {
    country?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
  metadata?: {
    appVersion?: string;
    platform?: string;
    language?: string;
    referrer?: string;
  };
}

/**
 * Interface for session update
 */
export interface UpdateSessionDto {
  lastUsedAt?: Date;
  isActive?: boolean;
  securityInfo?: {
    isSuspicious: boolean;
    riskScore: number;
    flags: string[];
  };
}
