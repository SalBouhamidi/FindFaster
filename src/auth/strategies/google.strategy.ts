import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { GoogleProfile } from '../interfaces/auth.interface';

/**
 * Google OAuth 2.0 Passport Strategy
 * Handles Google authentication flow
 */
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private configService: ConfigService) {
    super({
      clientID: configService.get<string>('google.clientId')!,
      clientSecret: configService.get<string>('google.clientSecret')!,
      callbackURL: configService.get<string>('google.callbackURL')!,
      scope: ['email', 'profile'],
    });
  }

  /**
   * Validate Google OAuth callback
   * @param accessToken Google access token
   * @param refreshToken Google refresh token
   * @param profile Google user profile
   * @param done Passport callback
   */
  validate(
    accessToken: string,
    refreshToken: string,
    profile: GoogleProfile,
    done: VerifyCallback,
  ): void {
    try {
      const { id, displayName, emails, photos } = profile;

      const userEmail = emails[0]?.value;
      if (!userEmail) {
        return done(new Error('No email found in Google profile'), false);
      }

      const googleUser = {
        googleId: id,
        fullName: displayName,
        email: userEmail,
        profilePicture:
          photos && photos.length > 0 ? photos[0]?.value : undefined,
        accessToken,
        refreshToken,
      };

      return done(null, googleUser);
    } catch (error) {
      return done(error, false);
    }
  }
}
