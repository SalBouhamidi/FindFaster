import { PartialType } from '@nestjs/swagger';
import { CreateRoleDto } from '@roles/dtos/create-role.dto';

export class UpdateRoleDto extends PartialType(CreateRoleDto) {}
