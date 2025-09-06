import { IsString, IsOptional, IsBoolean, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateRoleDto {
  @ApiProperty({
    description: 'Unique role name identifier',
    enum: ['user', 'admin'],
    example: 'user',
    required: true,
  })
  @IsEnum(['user', 'admin'], {
    message: 'Role name must be either "user" or "admin"',
  })
  name: 'user' | 'admin';

  @ApiProperty({
    description: 'Human-readable display name for the role',
    example: 'Standard User',
    required: true,
    minLength: 1,
    maxLength: 100,
  })
  @IsString()
  displayName: string;

  @ApiProperty({
    description: 'Whether the role should be active upon creation',
    example: true,
    required: false,
    default: true,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiProperty({
    description: 'Whether this should be the default role for new users',
    example: false,
    required: false,
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  isDefault?: boolean;
}
