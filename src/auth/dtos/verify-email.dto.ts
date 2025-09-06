import { IsString } from 'class-validator';

/**
 * DTO for email verification request
 * Validates verification token from email
 */
export class VerifyEmailDto {
  /**
   * Email verification token from email
   */
  @IsString()
  token: string;
}
