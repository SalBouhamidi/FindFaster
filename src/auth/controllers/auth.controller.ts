import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  HttpStatus,
  Query,
  ValidationPipe,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
  ApiResponse,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthService } from '../services/auth.service';
import { GoogleAuthGuard } from '../guards/google-auth.guard';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { GoogleAuthDto } from '../dtos/google-auth.dto';
import { RegisterDto } from '../dtos/register.dto';
import { LoginDto } from '../dtos/login.dto';
import { ForgotPasswordDto } from '../dtos/forgot-password.dto';
import { ResetPasswordDto } from '../dtos/reset-password.dto';
import { VerifyEmailDto } from '../dtos/verify-email.dto';
import { GetUser } from '../../common/decorators/get-user.decorator';
import { AuthenticatedUser } from '../interfaces/auth.interface';
import { RateLimitGuard, RateLimit } from '../../common/guards/rate-limit.guard';
import { AccountLockoutGuard } from '../../common/guards/account-lockout.guard';
import { GoogleTokenDto } from '../dtos/google-token.dto';

/**
 * Authentication controller
 * Handles all authentication-related HTTP requests
 */
@ApiTags('Auth')
@ApiBearerAuth('JWT-auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly authService: AuthService,
    private readonly accountLockoutGuard: AccountLockoutGuard,
  ) {}

  /**
   * Register a new user with email and password
   * @param registerDto Registration data
   * @param req Express request for security tracking
   * @param res Express response for cookies
   */
  @Post('register')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 10 * 60 * 1000, maxAttempts: 3 }) // 3 attempts per 10 minutes
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: RegisterDto })
  @ApiOkResponse({
    description: 'Registration successful',
    schema: {
      example: {
        message: 'Registration successful',
        user: {
          id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          role: 'user',
          emailVerified: false,
          isActive: true,
        },
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiBadRequestResponse({ description: 'Validation error' })
  async register(
    @Body() registerDto: RegisterDto,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    this.logger.log(`Registration attempt for ${registerDto.email}`, {
      ip: this.getClientIP(req),
      userAgent: req.headers['user-agent'],
    });

    const authResponse = await this.authService.register(registerDto, req);

    // Set cookies for registration (same as login)
    const isProduction = process.env.NODE_ENV === 'production';
    const cookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax' as const,
      maxAge: 15 * 60 * 1000, // 15 minutes
      path: '/',
    };

    // Set access token cookie
    res.cookie('access_token', authResponse.accessToken, cookieOptions);

    // Set refresh token cookie with longer expiry
    res.cookie('refresh_token', authResponse.refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/api/auth/refresh-token',
    });

    this.logger.log(`Registration successful for ${registerDto.email}`, {
      userId: authResponse.user.id,
      ip: this.getClientIP(req),
    });

    res.status(HttpStatus.CREATED).json({
      message: 'Registration successful',
      user: authResponse.user,
      accessToken: authResponse.accessToken,
      refreshToken: authResponse.refreshToken,
    });
  }

  /**
   * Login user with email and password
   * @param loginDto Login credentials
   * @param req Express request for security tracking
   * @param res Express response for cookies
   */
  @Post('login')
  @UseGuards(RateLimitGuard, AccountLockoutGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, maxAttempts: 5 }) // 5 attempts per 15 minutes
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({
    description: 'Login successful',
    schema: {
      example: {
        message: 'Login successful',
        user: {
          id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          role: 'user',
          emailVerified: true,
          isActive: true,
        },
        accessToken: 'eyJhbGciOi...',
        expiresIn: 900,
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    try {
      // Use the enhanced login method that includes security tracking
      const authResponse = await this.authService.login(
        loginDto.email,
        loginDto.password,
        req,
      );

      // Set secure HTTP-only cookie with access token
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax' as const,
        maxAge: 15 * 60 * 1000, // 15 minutes (matches access token expiry)
        path: '/',
      };

      // Set access token cookie
      res.cookie('access_token', authResponse.accessToken, cookieOptions);

      // Set refresh token cookie with longer expiry
      res.cookie('refresh_token', authResponse.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/api/auth/refresh-token', // Restrict refresh token to specific endpoint
      });

      res.json({
        message: 'Login successful',
        user: authResponse.user,
        accessToken: authResponse.accessToken,
        expiresIn: authResponse.expiresIn,
      });
    } catch (error) {
      this.logger.error(`Login failed for ${loginDto.email}`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        ip: this.getClientIP(req),
        userAgent: req.headers['user-agent'],
      });
      throw error;
    }
  }

  // Client-side token verification endpoint (with token)
  @Post('google/token')
  @ApiOperation({ summary: 'Authenticate with Google JWT token' })
  @ApiResponse({ status: 201, description: 'Google authentication successful' })
  @ApiBadRequestResponse({ description: 'Invalid Google token' })
  async googleTokenAuth(
    @Body() googleTokenDto: GoogleTokenDto, // ✅ This DTO has the token field
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    try {
      this.logger.log('Google token authentication attempt', {
        ip: this.getClientIP(req),
        userAgent: req.headers['user-agent'],
      });

      if (!googleTokenDto.termsAccepted) {
        throw new BadRequestException(
          'You must accept the terms and privacy policy',
        );
      }

      // Verify and decode the Google JWT token
      const googleUser = await this.authService.verifyGoogleToken(
        googleTokenDto.token,
      );

      const authResponse = await this.authService.googleAuth(
        googleUser,
        {
          termsAccepted: googleTokenDto.termsAccepted,
          subscribeUpdates: googleTokenDto.subscribeUpdates || false,
        },
        req,
      );

      // Set secure HTTP-only cookies
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax' as const,
        path: '/',
      };

      res.cookie('access_token', authResponse.accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000, // 15 minutes
      });

      res.cookie('refresh_token', authResponse.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/api/auth/refresh-token',
      });

      this.logger.log(
        `Google authentication successful for ${googleUser.email}`,
        {
          userId: authResponse.user.id,
          ip: this.getClientIP(req),
        },
      );

      res.status(HttpStatus.CREATED).json({
        message: 'Google authentication successful',
        user: authResponse.user,
        accessToken: authResponse.accessToken,
        refreshToken: authResponse.refreshToken,
      });
    } catch (error) {
      this.logger.error(
        `Google token authentication failed: ${error.message}`,
        {
          ip: this.getClientIP(req),
          error: error.stack,
        },
      );

      throw error;
    }
  }

  /**
   * Initiate Google OAuth login
   * Accepts user preferences as query parameters
   * @param req Express request
   * @param query Query parameters containing user preferences
   */
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Initiate Google OAuth' })
  @ApiResponse({ status: 302, description: 'Redirect to Google OAuth' })
  googleLogin(
    @Req() req: Request,
    @Query(new ValidationPipe({ transform: true })) query: GoogleAuthDto,
  ): void {
    // Store user preferences in session for callback
    req.session.authPreferences = {
      termsAccepted: Boolean(query.termsAccepted) || true, // Default to true
      subscribeUpdates: Boolean(query.subscribeUpdates) || false,
    };
  }

  /**
   * Google OAuth callback handler
   * Processes the Google OAuth response and creates/updates user
   * @param req Express request with user from Google strategy
   * @param res Express response
   */
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Google OAuth callback' })
  @ApiResponse({
    status: 302,
    description: 'Redirect to frontend after Google auth',
  })
  async googleCallback(
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    try {
      const googleUser = req.user as {
        googleId: string;
        fullName: string;
        email: string;
        profilePicture?: string;
      };
      const authPreferences = req.session.authPreferences;

      if (!authPreferences?.termsAccepted) {
        return res.redirect(
          `${process.env.FRONTEND_URL}/register?error=terms_not_accepted`,
        );
      }

      const authResponse = await this.authService.googleAuth(
        googleUser,
        authPreferences,
        req,
      );

      // Clear session data
      delete req.session.authPreferences;

      // Set secure HTTP-only cookies (align with email/password login flow)
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax' as const,
        path: '/',
      };

      // Access token cookie (short-lived)
      res.cookie('access_token', authResponse.accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000, // 15 minutes
      });

      // Refresh token cookie (longer-lived, restrict path to refresh endpoint)
      res.cookie('refresh_token', authResponse.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/api/auth/refresh-token',
      });

      // Redirect to frontend with success
      return res.redirect(`${process.env.FRONTEND_URL}/dashboard?auth=success`);
    } catch (error) {
      console.error('Google OAuth callback error:', error);
      return res.redirect(
        `${process.env.FRONTEND_URL}/login?error=auth_failed`,
      );
    }
  }

  /**
   * Get current user profile
   * Protected route that returns authenticated user's information
   * @param user Authenticated user from JWT token
   */
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiOkResponse({
    description: 'Current user profile',
    schema: {
      example: {
        id: '64a7b8c9d1e2f3g4h5i6j7k8',
        fullName: 'John Doe',
        email: 'john.doe@example.com',
        role: 'user',
        emailVerified: true,
        isActive: true,
        profilePicture: 'https://example.com/avatar.jpg',
      },
    },
  })
  async getProfile(
    @GetUser() user: AuthenticatedUser,
  ): Promise<AuthenticatedUser> {
    return this.authService.getUserProfile(user.id);
  }

  /**
   * Refresh user profile
   * Forces a fresh fetch of user data from database
   * @param user Authenticated user from JWT token
   */
  @Post('refresh')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Refresh user profile' })
  @ApiOkResponse({
    description: 'Refreshed user profile',
    schema: {
      example: {
        id: '64a7b8c9d1e2f3g4h5i6j7k8',
        fullName: 'John Doe',
        email: 'john.doe@example.com',
        role: 'user',
      },
    },
  })
  async refreshProfile(
    @GetUser() user: AuthenticatedUser,
  ): Promise<AuthenticatedUser> {
    return this.authService.getUserProfile(user.id);
  }

  /**
   * Logout user
   * Clears authentication cookies and invalidates current session
   * @param user Current authenticated user
   * @param req Express request
   * @param res Express response
   */
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Logout and clear auth cookies' })
  @ApiOkResponse({
    description: 'Logged out successfully',
    schema: {
      example: { message: 'Logged out successfully' },
    },
  })
  async logout(
    @GetUser() user: AuthenticatedUser,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    try {
      // Get refresh token from cookie to revoke specific session
      const refreshToken = req.cookies?.refresh_token as string;
      if (refreshToken) {
        await this.authService.revokeRefreshToken(refreshToken);
      }

      // Clear all auth-related cookies
      res.clearCookie('access_token', { path: '/' });
      res.clearCookie('refresh_token', { path: '/api/auth/refresh-token' });

      // Destroy session
      req.session.destroy((err) => {
        if (err) {
          this.logger.error('Failed to destroy session during logout', err);
        }
      });

      this.logger.log(`User logged out successfully`, {
        userId: user.id,
        email: user.email,
        ip: this.getClientIP(req),
      });

      res.status(HttpStatus.OK).json({ message: 'Logged out successfully' });
    } catch (error) {
      this.logger.error('Logout error', error);
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: 'Logout failed',
      });
    }
  }

  /**
   * Logout from all devices
   * Revokes all refresh tokens for the user
   * @param user Current authenticated user
   * @param req Express request
   * @param res Express response
   */
  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Logout from all devices' })
  @ApiOkResponse({
    description: 'Logged out from all devices successfully',
    schema: {
      example: { message: 'Logged out from all devices successfully' },
    },
  })
  async logoutAll(
    @GetUser() user: AuthenticatedUser,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    try {
      // Revoke all refresh tokens for this user
      await this.authService.revokeAllRefreshTokens(user.id);

      // Clear all auth-related cookies
      res.clearCookie('access_token', { path: '/' });
      res.clearCookie('refresh_token', { path: '/api/auth/refresh-token' });

      // Destroy session
      req.session.destroy((err) => {
        if (err) {
          this.logger.error('Failed to destroy session during logout all', err);
        }
      });

      this.logger.log(`User logged out from all devices`, {
        userId: user.id,
        email: user.email,
        ip: this.getClientIP(req),
      });

      res
        .status(HttpStatus.OK)
        .json({ message: 'Logged out from all devices successfully' });
    } catch (error) {
      this.logger.error('Logout all error', error);
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: 'Logout from all devices failed',
      });
    }
  }

  /**
   * Check authentication status (protected)
   * Returns authenticated user information
   * @param user Authenticated user
   */
  @Get('status')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Check authentication status (protected)' })
  @ApiOkResponse({
    description: 'Authentication status',
    schema: {
      example: {
        isAuthenticated: true,
        user: {
          id: '64a7b8c9d1e2f3g4h5i6j7k8',
          email: 'john.doe@example.com',
        },
      },
    },
  })
  checkAuthStatus(@GetUser() user: AuthenticatedUser): {
    isAuthenticated: boolean;
    user: AuthenticatedUser;
  } {
    return {
      isAuthenticated: true,
      user: user,
    };
  }

  /**
   * Check authentication status (public)
   * Returns whether the user is authenticated without requiring auth
   * @param user Authenticated user (optional)
   */
  @Get('status/public')
  @ApiOperation({ summary: 'Check authentication status (public)' })
  @ApiOkResponse({
    description: 'Authentication status',
    schema: {
      example: {
        isAuthenticated: false,
      },
    },
  })
  checkPublicAuthStatus(@GetUser() user?: AuthenticatedUser): {
    isAuthenticated: boolean;
    user?: AuthenticatedUser;
  } {
    return {
      isAuthenticated: !!user,
      user: user || undefined,
    };
  }

  /**
   * Send forgot password email
   * @param forgotPasswordDto Email for password reset
   * @param req Express request for security tracking
   */
  @Post('forgot-password')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 60 * 60 * 1000, maxAttempts: 3 }) // 3 attempts per hour
  @ApiOperation({ summary: 'Send password reset email' })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOkResponse({
    description: 'Password reset email flow initiated',
    schema: {
      example: { message: 'If the email exists, a reset link has been sent' },
    },
  })
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Req() req: Request,
  ): Promise<{ message: string }> {
    this.logger.log(`Password reset requested for ${forgotPasswordDto.email}`, {
      ip: this.getClientIP(req),
      userAgent: req.headers['user-agent'],
    });

    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  /**
   * Reset password with token
   * @param resetPasswordDto Token and new password
   */
  @Post('reset-password')
  @ApiOperation({ summary: 'Reset password with token' })
  @ApiBody({ type: ResetPasswordDto })
  @ApiOkResponse({
    description: 'Password reset successfully',
    schema: { example: { message: 'Password reset successfully' } },
  })
  @ApiBadRequestResponse({ description: 'Invalid or expired reset token' })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<{
    message: string;
  }> {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
    );
  }

  /**
   * Send email verification
   * @param user Authenticated user
   */
  @Post('send-verification')
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Send email verification' })
  @ApiOkResponse({
    description: 'Verification email sent',
    schema: { example: { message: 'Verification email sent' } },
  })
  async sendEmailVerification(@GetUser() user: AuthenticatedUser): Promise<{
    message: string;
  }> {
    return this.authService.sendEmailVerification(user.id);
  }

  /**
   * Verify email with token
   * @param verifyEmailDto Verification token
   */
  @Post('verify-email')
  @ApiOperation({ summary: 'Verify email with token' })
  @ApiBody({ type: VerifyEmailDto })
  @ApiOkResponse({
    description: 'Email verified successfully',
    schema: { example: { message: 'Email verified successfully' } },
  })
  @ApiBadRequestResponse({
    description: 'Invalid or expired verification token',
  })
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<{
    message: string;
  }> {
    return this.authService.verifyEmail(verifyEmailDto.token);
  }

  /**
   * Refresh access token using refresh token
   * @param req Express request (refresh token from cookie)
   * @param res Express response
   */
  @Post('refresh-token')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 5 * 60 * 1000, maxAttempts: 10 }) // 10 attempts per 5 minutes
  @ApiOperation({ summary: 'Refresh tokens using refresh token' })
  @ApiOkResponse({
    description: 'Token refreshed successfully',
    schema: {
      example: {
        message: 'Token refreshed successfully',
        expiresIn: 900,
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Invalid refresh token' })
  async refreshToken(@Req() req: Request, @Res() res: Response): Promise<void> {
    try {
      // Get refresh token from secure cookie
      const refreshToken = req.cookies?.refresh_token as string;

      if (!refreshToken) {
        res.status(HttpStatus.UNAUTHORIZED).json({
          message: 'Refresh token not found',
        });
        return;
      }

      const tokens = await this.authService.refreshTokens(refreshToken);

      // Update cookies with new tokens
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax' as const,
        path: '/',
      };

      res.cookie('access_token', tokens.accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000, // 15 minutes
      });

      res.cookie('refresh_token', tokens.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/api/auth/refresh-token',
      });

      res.status(HttpStatus.OK).json({
        message: 'Token refreshed successfully',
        expiresIn: tokens.expiresIn,
      });
    } catch (error) {
      this.logger.error('Token refresh failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        ip: this.getClientIP(req),
      });

      // Clear invalid refresh token cookie
      res.clearCookie('refresh_token', { path: '/api/auth/refresh-token' });

      res.status(HttpStatus.UNAUTHORIZED).json({
        message: 'Token refresh failed',
      });
    }
  }
   /*** Validates the JWT token from the extension and checks if the user has paid.
 * @param user Authenticated user from JWT token
 * @returns Object indicating token validity and payment status
 */
@Post('validate-and-check-payment')
@UseGuards(JwtAuthGuard)
@ApiOperation({ summary: 'Validate extension token and check user payment status' })
@ApiOkResponse({
  description: 'Token valid and user payment status returned',
  schema: {
    example: {
      isValid: true,
      isPaid: true,
    },
  },
})
@ApiUnauthorizedResponse({ description: 'Invalid or expired token' })
async validateAndCheckPayment(
  @GetUser() user: AuthenticatedUser,
): Promise<{ isValid: boolean; isPaid: boolean }> {
  this.logger.log(`Extension token validation and payment check for user: ${user.email}`, {
    userId: user.id,
  });

  const isPaid = await this.authService.checkUserPaymentStatus(user.id);

  return {
    isValid: true,
    isPaid: isPaid,
  };
}

private getClientIP(req: Request): string { // <<-- Is method ko yahan wapas daalein
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    (req.headers['x-real-ip'] as string) ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}
}