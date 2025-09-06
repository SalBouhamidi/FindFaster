import {
  IsString,
  IsEmail,
  IsEnum,
  IsBoolean,
  IsOptional,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { UserRole } from '../../users/schemas/user.schema';

/**
 * DTO for creating a new user via Google OAuth
 */
export class CreateUserDto {
  /**
   * User's full name from Google
   */
  @IsString()
  fullName: string;

  /**
   * User's email from Google
   */
  @IsEmail()
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  email: string;

  /**
   * Hashed password for local users
   */
  @IsOptional()
  @IsString()
  password?: string;

  /**
   * Google OAuth ID
   */
  @IsOptional()
  @IsString()
  googleId?: string;

  /**
   * Profile picture URL from Google
   */
  @IsOptional()
  @IsString()
  profilePicture?: string;

  /**
   * User role
   */
  @IsEnum(UserRole)
  role: UserRole;

  /**
   * Terms acceptance status
   */
  @IsBoolean()
  termsAccepted: boolean;

  /**
   * Updates subscription preference
   */
  @IsOptional()
  @IsBoolean()
  subscribeUpdates?: boolean;
}

/**
 * DTO for updating user preferences
 */
export class UpdateUserPreferencesDto {
  /**
   * Optional: subscribe to updates
   */
  @IsOptional()
  @IsBoolean()
  subscribeUpdates?: boolean;
}
