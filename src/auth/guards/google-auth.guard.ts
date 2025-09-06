import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Google OAuth guard
 * Initiates Google OAuth flow
 */
@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {}
