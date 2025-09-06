import {
  IsEmail,
  IsString,
  MinLength,
  IsBoolean,
  IsOptional,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { IsStrongPassword } from '../../common/validators/password.validator';

/**
 * DTO for user registration
 * Validates input data for creating new users
 */
export class RegisterDto {
  /**
   * User's full name
   */
  @IsString()
  @MinLength(2, { message: 'Full name must be at least 2 characters long' })
  @Transform(({ value }: { value: string }) => value?.trim())
  fullName: string;

  /**
   * User's email address
   */
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  email: string;

  /**
   * User's password - must meet security requirements
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
    forbidPersonalInfo: true,
  })
  password: string;

  /**
   * User must accept terms of service
   */
  @IsBoolean()
  @Transform(({ value }) => value === true || value === 'true')
  termsAccepted: boolean;

  /**
   * Optional: subscribe to updates
   */
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value === true || value === 'true')
  subscribeUpdates?: boolean;
}
