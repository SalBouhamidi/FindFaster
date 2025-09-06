import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString, IsNotEmpty } from 'class-validator';

/**
 * DTO for Google OAuth registration preferences
 * Captures user preferences during Google OAuth flow
 */
export class GoogleTokenDto {
  @ApiProperty({
    description: 'Google JWT token from @react-oauth/google',
    example: 'eyJhbGciOiJSUzI1NiIsImtpZCI6...',
  })
  @IsString()
  @IsNotEmpty()
  token: string;

  /**
   * User must accept terms of service
   */
  @ApiProperty({
    description: 'User acceptance of terms and privacy policy',
    example: true,
  })
  @IsBoolean()
  termsAccepted: boolean;

  /**
   * Optional: subscribe to updates
   */
  @ApiProperty({
    description: 'Subscribe to email updates',
    example: false,
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  subscribeUpdates?: boolean;
}
