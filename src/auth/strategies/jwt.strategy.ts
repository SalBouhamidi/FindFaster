import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersRepository } from '@users/repositories/users.repository';
import { JwtPayload, AuthenticatedUser } from '@auth/interfaces/auth.interface';
import { objectIdToString } from '@common/utils/type-guards';
import type { Request } from 'express';

/**
 * JWT Passport Strategy
 * Validates JWT tokens for protected routes
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private usersRepository: UsersRepository,
  ) {
    // Rely on main.ts environment guard to ensure JWT_SECRET presence
    const secretOrKey = configService.get<string>('jwt.secret')!;

    // Safe cookie extractor with explicit types to satisfy eslint rules
    const cookieExtractor = (req: Request | undefined): string | null => {
      if (!req || typeof req !== 'object') return null;
      const token = (req as { cookies?: Record<string, unknown> }).cookies
        ?.access_token;
      return typeof token === 'string' ? token : null;
    };

    super({
      // Support both Bearer header and secure cookie for access token
      jwtFromRequest: ExtractJwt.fromExtractors([
        cookieExtractor,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey,
    });
  }

  /**
   * Validate JWT payload and return user
   * @param payload JWT payload
   * @returns Authenticated user
   */
  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    // Prevent using refresh tokens for protected endpoints
    if (payload.type === 'refresh') {
      throw new UnauthorizedException('Invalid token type for this endpoint');
    }
    const user = await this.usersRepository.findById(payload.sub);

    if (!user || !user.isActive) {
      throw new UnauthorizedException('User not found or inactive');
    }

    return {
      id: objectIdToString(user._id),
      fullName: user.fullName,
      email: user.email,
      googleId: user.googleId,
      profilePicture: user.profilePicture,
      role: user.role,
      termsAccepted: user.termsAccepted,
      subscribeUpdates: user.subscribeUpdates,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
    };
  }
}
