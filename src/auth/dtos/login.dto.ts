import { IsEmail, IsString, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';

/**
 * DTO for user login
 * Validates input data for user authentication
 */
export class LoginDto {
  /**
   * User's email address
   */
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  email: string;

  /**
   * User's password
   */
  @IsString()
  @MinLength(1, { message: 'Password is required' })
  password: string;
}
