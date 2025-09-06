import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  HttpStatus,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiParam,
  ApiBody,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiNotFoundResponse,
  ApiConflictResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RolesService } from '@roles/services/roles.service';
import { CreateRoleDto } from '@roles/dtos/create-role.dto';
import { UpdateRoleDto } from '@roles/dtos/update-role.dto';

import { JwtAuthGuard } from '@auth/guards/jwt-auth.guard';
import { RolesGuard } from '@roles/guards/roles.guard';
import { RequireRoles } from '@common/decorators/roles.decorator';

@ApiTags('Roles Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('roles')
@ApiUnauthorizedResponse({
  description: 'Unauthorized - Invalid or missing JWT token',
})
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post()
  @RequireRoles('admin')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new role',
    description:
      'Creates a new role in the system. Only administrators can create roles.',
  })
  @ApiBody({ type: CreateRoleDto, description: 'Role data to create' })
  @ApiCreatedResponse({
    description: 'Role created successfully',
    schema: {
      example: {
        statusCode: 201,
        message: 'Role created successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          name: 'user',
          displayName: 'Standard User',
          isActive: true,
          isDefault: false,
          createdAt: '2024-01-20T10:30:00.000Z',
          updatedAt: '2024-01-20T10:30:00.000Z',
        },
      },
    },
  })
  @ApiConflictResponse({ description: 'Role with this name already exists' })
  @ApiForbiddenResponse({ description: 'Forbidden - Insufficient permissions' })
  @ApiBadRequestResponse({ description: 'Invalid role data provided' })
  async create(@Body() createRoleDto: CreateRoleDto) {
    const role = await this.rolesService.create(createRoleDto);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'Role created successfully',
      data: role,
    };
  }

  @Get()
  @ApiOperation({
    summary: 'Get all roles',
    description: 'Retrieves all roles in the system, both active and inactive.',
  })
  @ApiOkResponse({
    description: 'Roles retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Roles retrieved successfully',
        data: [
          {
            _id: '64a7b8c9d1e2f3g4h5i6j7k8',
            name: 'user',
            displayName: 'User',
            isActive: true,
            isDefault: true,
            createdAt: '2024-01-20T10:30:00.000Z',
            updatedAt: '2024-01-20T10:30:00.000Z',
          },
          {
            _id: '64a7b8c9d1e2f3g4h5i6j7k9',
            name: 'admin',
            displayName: 'Administrator',
            isActive: true,
            isDefault: false,
            createdAt: '2024-01-20T10:30:00.000Z',
            updatedAt: '2024-01-20T10:30:00.000Z',
          },
        ],
      },
    },
  })
  async findAll() {
    const roles = await this.rolesService.findAll();
    return {
      statusCode: HttpStatus.OK,
      message: 'Roles retrieved successfully',
      data: roles,
    };
  }

  @Get('active')
  @ApiOperation({
    summary: 'Get active roles',
    description:
      'Retrieves only the roles that are currently active in the system.',
  })
  @ApiOkResponse({
    description: 'Active roles retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Active roles retrieved successfully',
        data: [
          {
            _id: '64a7b8c9d1e2f3g4h5i6j7k8',
            name: 'user',
            displayName: 'User',
            isActive: true,
            isDefault: true,
            createdAt: '2024-01-20T10:30:00.000Z',
            updatedAt: '2024-01-20T10:30:00.000Z',
          },
        ],
      },
    },
  })
  async findActive() {
    const roles = await this.rolesService.findAllActive();
    return {
      statusCode: HttpStatus.OK,
      message: 'Active roles retrieved successfully',
      data: roles,
    };
  }

  @Get('default')
  @ApiOperation({
    summary: 'Get default role',
    description: 'Retrieves the default role that is assigned to new users.',
  })
  @ApiOkResponse({
    description: 'Default role retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Default role retrieved successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          name: 'user',
          displayName: 'User',
          isActive: true,
          isDefault: true,
          createdAt: '2024-01-20T10:30:00.000Z',
          updatedAt: '2024-01-20T10:30:00.000Z',
        },
      },
    },
  })
  async getDefault() {
    const role = await this.rolesService.getDefaultRole();
    return {
      statusCode: HttpStatus.OK,
      message: 'Default role retrieved successfully',
      data: role,
    };
  }

  @Get('statistics')
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Get role statistics',
    description:
      'Retrieves statistical information about roles in the system. Only administrators can access this endpoint.',
  })
  @ApiOkResponse({
    description: 'Statistics retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Statistics retrieved successfully',
        data: {
          total: 2,
          active: 2,
          inactive: 0,
          userRoles: 1,
          adminRoles: 1,
        },
      },
    },
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async getStatistics() {
    const statistics = await this.rolesService.getRoleStatistics();
    return {
      statusCode: HttpStatus.OK,
      message: 'Statistics retrieved successfully',
      data: statistics,
    };
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get role by ID',
    description: 'Retrieves a specific role by its unique identifier.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the role',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiOkResponse({
    description: 'Role retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Role retrieved successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          name: 'user',
          displayName: 'Standard User',
          isActive: true,
          isDefault: false,
          createdAt: '2024-01-20T10:30:00.000Z',
          updatedAt: '2024-01-20T10:30:00.000Z',
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'Role not found' })
  @ApiBadRequestResponse({ description: 'Invalid role ID format' })
  async findById(@Param('id') id: string) {
    const role = await this.rolesService.findById(id);
    return {
      statusCode: HttpStatus.OK,
      message: 'Role retrieved successfully',
      data: role,
    };
  }

  @Put(':id')
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Update role',
    description:
      'Updates an existing role with new information. Only administrators can update roles.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the role to update',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiBody({ type: UpdateRoleDto, description: 'Updated role data' })
  @ApiOkResponse({
    description: 'Role updated successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Role updated successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          name: 'admin',
          displayName: 'System Administrator',
          isActive: true,
          isDefault: false,
          createdAt: '2024-01-20T10:30:00.000Z',
          updatedAt: '2024-01-20T15:45:00.000Z',
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'Role not found' })
  @ApiConflictResponse({ description: 'Role name already exists' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  @ApiBadRequestResponse({ description: 'Invalid role data or ID format' })
  async update(@Param('id') id: string, @Body() updateRoleDto: UpdateRoleDto) {
    const role = await this.rolesService.update(id, updateRoleDto);
    return {
      statusCode: HttpStatus.OK,
      message: 'Role updated successfully',
      data: role,
    };
  }

  @Delete(':id')
  @RequireRoles('admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete role',
    description:
      'Permanently deletes a role from the system. Default roles cannot be deleted. Only administrators can delete roles.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the role to delete',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiOkResponse({
    description: 'Role deleted successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Role deleted successfully',
      },
    },
  })
  @ApiNotFoundResponse({ description: 'Role not found' })
  @ApiBadRequestResponse({
    description: 'Cannot delete default role or invalid ID format',
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async remove(@Param('id') id: string) {
    await this.rolesService.remove(id);
    return {
      statusCode: HttpStatus.OK,
      message: 'Role deleted successfully',
    };
  }
}
