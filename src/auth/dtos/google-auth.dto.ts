import { IsBoolean, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

/**
 * DTO for Google OAuth registration preferences
 * Captures user preferences during Google OAuth flow
 */
export class GoogleAuthDto {
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
