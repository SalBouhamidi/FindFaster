import { IsString, IsArray, IsMongoId } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AssignUserRolesDto {
  @ApiProperty({
    description: 'Array of role IDs to assign to the user',
    example: ['64a7b8c9d1e2f3g4h5i6j7k8', '64a7b8c9d1e2f3g4h5i6j7k9'],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  @IsMongoId({
    each: true,
    message: 'Each role ID must be a valid MongoDB ObjectId',
  })
  roleIds: string[];
}
