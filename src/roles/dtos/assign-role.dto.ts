import { IsString, IsEnum, IsMongoId } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AssignRoleDto {
  @ApiProperty({
    description: 'MongoDB ObjectId of the user to assign the role to',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
    required: true,
  })
  @IsString()
  @IsMongoId({ message: 'Invalid user ID format' })
  userId: string;

  @ApiProperty({
    description: 'Role to assign to the user',
    enum: ['user', 'admin'],
    example: 'user',
    required: true,
  })
  @IsEnum(['user', 'admin'], {
    message: 'Role must be either "user" or "admin"',
  })
  role: 'user' | 'admin';
}
