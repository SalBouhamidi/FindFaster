import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { Types } from 'mongoose';
import { RolesRepository } from '@roles/repositories/roles.repository';
import { CreateRoleDto } from '@roles/dtos/create-role.dto';
import { UpdateRoleDto } from '@roles/dtos/update-role.dto';
import { RoleDocument } from '@roles/schemas/role.schema';

@Injectable()
export class RolesService {
  constructor(private readonly rolesRepository: RolesRepository) {}

  async create(createRoleDto: CreateRoleDto): Promise<RoleDocument> {
    const existingRole = await this.rolesRepository.findByName(
      createRoleDto.name,
    );
    if (existingRole) {
      throw new ConflictException(
        `Role '${createRoleDto.name}' already exists`,
      );
    }

    if (createRoleDto.isDefault === true) {
      await this.rolesRepository.setAsDefault(createRoleDto.name);
    }

    return this.rolesRepository.create(createRoleDto);
  }

  async findById(id: string | Types.ObjectId): Promise<RoleDocument> {
    const role = await this.rolesRepository.findById(id);
    if (!role) {
      throw new NotFoundException('Role not found');
    }
    return role;
  }

  async findByName(name: string): Promise<RoleDocument> {
    const role = await this.rolesRepository.findByName(name);
    if (!role) {
      throw new NotFoundException(`Role '${name}' not found`);
    }
    return role;
  }

  async findAllActive(): Promise<RoleDocument[]> {
    return this.rolesRepository.findActiveRoles();
  }

  async findAll(): Promise<RoleDocument[]> {
    return this.rolesRepository.findAll();
  }

  async update(
    id: string | Types.ObjectId,
    updateRoleDto: UpdateRoleDto,
  ): Promise<RoleDocument> {
    const existingRole = await this.findById(id);

    if (updateRoleDto.name && updateRoleDto.name !== existingRole.name) {
      const nameExists = await this.rolesRepository.existsByName(
        updateRoleDto.name,
      );
      if (nameExists) {
        throw new ConflictException(
          `Role '${updateRoleDto.name}' already exists`,
        );
      }
    }

    if (updateRoleDto.isDefault && !existingRole.isDefault) {
      await this.rolesRepository.setAsDefault(
        updateRoleDto.name || existingRole.name,
      );
    }

    const updatedRole = await this.rolesRepository.updateById(
      id,
      updateRoleDto,
    );
    if (!updatedRole) {
      throw new NotFoundException('Role not found');
    }

    return updatedRole;
  }

  async remove(id: string | Types.ObjectId): Promise<void> {
    const role = await this.findById(id);

    if (role.isDefault) {
      throw new BadRequestException('Cannot delete the default role');
    }

    const deleted = await this.rolesRepository.deleteById(id);
    if (!deleted) {
      throw new NotFoundException('Role not found');
    }
  }
  async getDefaultRole(): Promise<RoleDocument> {
    const defaultRole = await this.rolesRepository.findDefaultRole();
    if (!defaultRole) {
      return this.findByName('user');
    }
    return defaultRole;
  }

  userHasRole(userRole: string, requiredRole: string): boolean {
    if (userRole === 'admin') {
      return true;
    }
    return userRole === requiredRole;
  }

  isAdmin(userRole: string): boolean {
    return userRole === 'admin';
  }

  isUser(userRole: string): boolean {
    return userRole === 'user';
  }

  getRoleLevel(roleName: string): number {
    const levels: Record<string, number> = {
      user: 1,
      admin: 10,
    };
    return levels[roleName] ?? 0;
  }

  hasHigherPrivileges(roleA: string, roleB: string): boolean {
    return this.getRoleLevel(roleA) > this.getRoleLevel(roleB);
  }

  async initializeDefaultRoles(): Promise<void> {
    const defaultRoles: CreateRoleDto[] = [
      {
        name: 'user',
        displayName: 'User',
        isActive: true,
        isDefault: true,
      },
      {
        name: 'admin',
        displayName: 'Administrator',
        isActive: true,
        isDefault: false,
      },
    ];

    for (const roleData of defaultRoles) {
      try {
        const exists = await this.rolesRepository.existsByName(roleData.name);
        if (!exists) {
          await this.rolesRepository.create(roleData);
        }
      } catch (error: unknown) {
        const errorMessage =
          error instanceof Error ? error.message : 'Unknown error';
        console.error(`Failed to create role ${roleData.name}:`, errorMessage);
      }
    }
  }

  async getRoleStatistics(): Promise<{
    total: number;
    active: number;
    inactive: number;
    userRoles: number;
    adminRoles: number;
  }> {
    return this.rolesRepository.getStatistics();
  }

  validateRoleName(roleName: string): boolean {
    const validRoles = ['user', 'admin'];
    if (!validRoles.includes(roleName)) {
      throw new BadRequestException(
        `Invalid role name. Must be one of: ${validRoles.join(', ')}`,
      );
    }
    return true;
  }
}
