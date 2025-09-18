import { Module, forwardRef } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';
import { GoogleStrategy } from './strategies/google.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { UsersModule } from '../users/users.module';
import { TokensModule } from '../tokens/tokens.module';
import { EmailModule } from '../email/email.module';
import { RolesGuard } from './guards/roles.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { RolesModule } from '../roles/roles.module';
import { RateLimitGuard } from '../common/guards/rate-limit.guard';
import { AccountLockoutGuard } from '../common/guards/account-lockout.guard';
import { SessionsModule } from '../sessions';

/**
 * Authentication module
 * Configures authentication services, strategies, and controllers
 */
@Module({
  imports: [
    forwardRef(() => UsersModule),
    RolesModule,
    TokensModule,
    EmailModule,
    SessionsModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('jwt.secret'),
        expiresIn: configService.get<string>('jwt.expiresIn'),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    GoogleStrategy,
    LocalStrategy,
    JwtStrategy,
    RolesGuard,
    PermissionsGuard,
    RateLimitGuard,
    AccountLockoutGuard,
  ],
  exports: [
    AuthService,
    JwtStrategy,
    RolesGuard,
    PermissionsGuard,
    RateLimitGuard,
    AccountLockoutGuard,
  ],
})
export class AuthModule {}
