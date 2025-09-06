import { IsEmail } from 'class-validator';
import { Transform } from 'class-transformer';

/**
 * DTO for forgot password request
 * Validates email input for password reset
 */
export class ForgotPasswordDto {
  /**
   * User's email address
   */
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  email: string;
}
