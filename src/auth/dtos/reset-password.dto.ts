import { IsString, MinLength } from 'class-validator';
import { IsStrongPassword } from '../../common/validators/password.validator';

/**
 * DTO for reset password request
 * Validates new password and reset token
 */
export class ResetPasswordDto {
  /**
   * Password reset token from email
   */
  @IsString()
  token: string;

  /**
   * New password - must meet security requirements
   */
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @IsStrongPassword({
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    forbidCommonPasswords: true,
  })
  newPassword: string;
}
