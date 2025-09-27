import { Module, OnModuleInit } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Role, RoleSchema } from './schemas/role.schema';
import { RolesRepository } from './repositories/roles.repository';
import { RolesService } from './services/roles.service';
import { RoleAssignmentService } from './services/role-assignment.service';
import { RolesController } from './controllers/roles.controller';
import { RolesGuard } from './guards/roles.guard';

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
