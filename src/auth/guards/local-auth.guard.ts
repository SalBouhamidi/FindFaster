import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Local authentication guard
 * Protects routes with email/password authentication
 */
@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
