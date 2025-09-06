import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

/**
 * Session Extractor Service
 * Extracts current session information from JWT tokens
 * Follows Single Responsibility Principle
 */
@Injectable()
export class SessionExtractorService {
  private readonly logger = new Logger(SessionExtractorService.name);

  constructor(private readonly jwtService: JwtService) {}

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
   * Type guard for JWT payload
   */
  private isJwtPayload(obj: unknown): obj is { jti?: string; sub?: string } {
    return obj !== null && typeof obj === 'object' && 'jti' in obj;
  }

  /**
   * Safe JWT decode with type checking
   */
  private safeJwtDecode(token: string): { jti?: string; sub?: string } | null {
    try {
      // Explicitly type as unknown to handle the any return type safely
      const decoded: unknown = this.jwtService.decode(token);
      return this.isJwtPayload(decoded) ? decoded : null;
    } catch {
      return null;
    }
  }

  /**
   * Extract current session ID from request
   */
  extractCurrentSessionId(request: Request): string | null {
    try {
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
      }

      const token = authHeader.substring(7);
      const decoded = this.safeJwtDecode(token);

      if (!decoded || !decoded.jti) {
        this.logger.warn('JWT token missing jti (JWT ID)');
        return null;
      }

      return decoded.jti;
    } catch (error: unknown) {
      this.logger.error(
        `Failed to extract session ID: ${this.getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Extract user ID from request
   */
  extractUserId(request: Request): string | null {
    try {
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
      }

      const token = authHeader.substring(7);
      const decoded = this.safeJwtDecode(token);

      if (!decoded || !decoded.sub) {
        this.logger.warn('JWT token missing sub (subject)');
        return null;
      }

      return decoded.sub;
    } catch (error: unknown) {
      this.logger.error(
        `Failed to extract user ID: ${this.getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Validate if token belongs to user
   */
  validateTokenOwnership(request: Request, userId: string): boolean {
    try {
      const tokenUserId = this.extractUserId(request);
      return tokenUserId === userId;
    } catch (error: unknown) {
      this.logger.error(
        `Failed to validate token ownership: ${this.getErrorMessage(error)}`,
      );
      return false;
    }
  }
}
