import { Module, OnModuleInit } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Role, RoleSchema } from '@roles/schemas/role.schema';
import { RolesRepository } from '@roles/repositories/roles.repository';
import { RolesService } from '@roles/services/roles.service';
import { RoleAssignmentService } from '@roles/services/role-assignment.service';
import { RolesController } from '@roles/controllers/roles.controller';
import { RolesGuard } from '@roles/guards/roles.guard';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Role.name, schema: RoleSchema }]),
  ],
  controllers: [RolesController],
  providers: [RolesRepository, RolesService, RolesGuard, RoleAssignmentService],
  exports: [RolesService, RolesGuard, RolesRepository, RoleAssignmentService],
})
export class RolesModule implements OnModuleInit {
  constructor(private readonly rolesService: RolesService) {}

  async onModuleInit() {
    await this.rolesService.initializeDefaultRoles();
  }
}
