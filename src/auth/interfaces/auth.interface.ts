import { Request } from 'express';
import { UserRole } from '../../users/schemas/user.schema';
import { Types } from 'mongoose';

/**
 * JWT payload interface
 */
export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  type: 'access' | 'refresh';
  jti?: string;
  iat?: number;
  exp?: number;
}

/**
 * Authenticated user interface
 */
export interface AuthenticatedUser {
  id: string;
  fullName: string;
  email: string;
  googleId?: string;
  profilePicture?: string;
  role: UserRole;
  termsAccepted?: boolean;
  subscribeUpdates?: boolean;
  emailVerified: boolean;
  isActive: boolean;
}

/**
 * Authentication response interface
 */
export interface AuthResponse {
  user: AuthenticatedUser;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * Token refresh response interface
 */
export interface TokenRefreshResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * Google profile interface
 */
export interface GoogleProfile {
  id: string;
  displayName: string;
  emails: Array<{ value: string; verified: boolean }>;
  photos?: Array<{ value: string }>;
}

/**
 * Extended request interface with user
 */
export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}

/**
 * Token document interface for database operations
 */
export interface TokenDocument {
  _id: Types.ObjectId | string;
  userId: string | Types.ObjectId;
  type: string;
  token: string;
  expiresAt: Date;
  isRevoked: boolean;
  deviceInfo?: string;
  ipAddress?: string;
  userAgent?: string;
  lastUsedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}
