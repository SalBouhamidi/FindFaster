import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
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
  ApiQuery,
  ApiOkResponse,
  ApiCreatedResponse,
  ApiNotFoundResponse,
  ApiConflictResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { UsersService } from '../services/users.service';
import { CreateUserDto } from '../dtos/create-user.dto';
import { UpdateUserDto } from '../dtos/update-user.dto';
import { AssignUserRolesDto } from '../dtos/assign-user-roles.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { RequireRoles } from '../../common/decorators/roles.decorator';
import { GetUser } from '../../common/decorators/get-user.decorator';
import { AuthenticatedUser } from '../../auth/interfaces/auth.interface';

/**
 * Users controller
 * Handles user-related HTTP requests
 */
@ApiTags('Users Management')
@ApiBearerAuth('JWT-auth')
@UseGuards(JwtAuthGuard)
@Controller('users')
@ApiUnauthorizedResponse({
  description: 'Unauthorized - Invalid or missing JWT token',
})
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new user',
    description:
      'Creates a new user in the system with default "user" role if no roles specified. Only administrators can create users.',
  })
  @ApiBody({ type: CreateUserDto, description: 'User data to create' })
  @ApiCreatedResponse({
    description: 'User created successfully',
    schema: {
      example: {
        statusCode: 201,
        message: 'User created successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          roles: [
            {
              _id: '64a7b8c9d1e2f3g4h5i6j7k9',
              name: 'user',
              displayName: 'User',
            },
          ],
          isActive: true,
          emailVerified: false,
          createdAt: '2024-01-20T10:30:00.000Z',
          updatedAt: '2024-01-20T10:30:00.000Z',
        },
      },
    },
  })
  @ApiConflictResponse({ description: 'User with this email already exists' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  @ApiBadRequestResponse({
    description: 'Invalid user data or role IDs provided',
  })
  async create(@Body() createUserDto: CreateUserDto) {
    const user = await this.usersService.create(createUserDto);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'User created successfully',
      data: user,
    };
  }

  @Get()
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Get all users',
    description:
      'Retrieves all users with pagination and filtering options. Only administrators can access this endpoint.',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10)',
    example: 10,
  })
  @ApiQuery({
    name: 'search',
    required: false,
    type: String,
    description: 'Search term for name or email',
    example: 'john',
  })
  @ApiQuery({
    name: 'isActive',
    required: false,
    type: Boolean,
    description: 'Filter by active status',
    example: true,
  })
  @ApiQuery({
    name: 'emailVerified',
    required: false,
    type: Boolean,
    description: 'Filter by email verification status',
    example: true,
  })
  @ApiOkResponse({
    description: 'Users retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Users retrieved successfully',
        data: {
          users: [
            {
              _id: '64a7b8c9d1e2f3g4h5i6j7k8',
              fullName: 'John Doe',
              email: 'john.doe@example.com',
              roles: [
                {
                  _id: '64a7b8c9d1e2f3g4h5i6j7k9',
                  name: 'user',
                  displayName: 'User',
                },
              ],
              isActive: true,
              emailVerified: true,
              createdAt: '2024-01-20T10:30:00.000Z',
            },
          ],
          total: 25,
          page: 1,
          totalPages: 3,
        },
      },
    },
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async findAll(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
    @Query('search') search?: string,
    @Query('isActive')
    isActive?: boolean,
    @Query('emailVerified')
    emailVerified?: boolean,
  ) {
    const result = await this.usersService.findAll(
      page || 1,
      limit || 10,
      search,
      isActive,
      emailVerified,
    );
    return {
      statusCode: HttpStatus.OK,
      message: 'Users retrieved successfully',
      data: result,
    };
  }

  @Get('active')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Get active users',
    description:
      'Retrieves only active users with pagination. Only administrators can access this endpoint.',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10)',
    example: 10,
  })
  @ApiOkResponse({
    description: 'Active users retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Active users retrieved successfully',
        data: {
          users: [],
          total: 10,
          page: 1,
          totalPages: 1,
        },
      },
    },
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async findActiveUsers(
    @Query('page') page?: number,
    @Query('limit') limit?: number,
  ) {
    const result = await this.usersService.findActiveUsers(
      page || 1,
      limit || 10,
    );
    return {
      statusCode: HttpStatus.OK,
      message: 'Active users retrieved successfully',
      data: result,
    };
  }

  @Get('search')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Search users',
    description:
      'Search users by name or email with pagination. Only administrators can access this endpoint.',
  })
  @ApiQuery({
    name: 'q',
    required: true,
    type: String,
    description: 'Search term',
    example: 'john',
  })
  @ApiQuery({
    name: 'page',
    required: false,
    type: Number,
    description: 'Page number (default: 1)',
    example: 1,
  })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Items per page (default: 10)',
    example: 10,
  })
  @ApiOkResponse({
    description: 'Search results retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Search results retrieved successfully',
        data: {
          users: [],
          total: 5,
          page: 1,
          totalPages: 1,
        },
      },
    },
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  @ApiBadRequestResponse({ description: 'Search term is required' })
  async searchUsers(
    @Query('q') searchTerm: string,
    @Query('page') page?: number,
    @Query('limit') limit?: number,
  ) {
    const result = await this.usersService.searchUsers(
      searchTerm,
      page || 1,
      limit || 10,
    );
    return {
      statusCode: HttpStatus.OK,
      message: 'Search results retrieved successfully',
      data: result,
    };
  }

  @Get('profile')
  @ApiOperation({
    summary: 'Get current user profile',
    description: "Retrieves the authenticated user's profile information.",
  })
  @ApiOkResponse({
    description: 'Profile retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Profile retrieved successfully',
        data: {
          id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          roles: ['user'],
          primaryRole: 'user',
          profilePicture: 'https://example.com/avatar.jpg',
        },
      },
    },
  })
  getProfile(@GetUser() user: AuthenticatedUser) {
    return {
      statusCode: HttpStatus.OK,
      message: 'Profile retrieved successfully',
      data: user,
    };
  }

  @Get('statistics')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Get user statistics',
    description:
      'Retrieves statistical information about users in the system. Only administrators can access this endpoint.',
  })
  @ApiOkResponse({
    description: 'Statistics retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Statistics retrieved successfully',
        data: {
          total: 150,
          active: 142,
          inactive: 8,
          verified: 135,
          unverified: 15,
          locked: 3,
          withRoles: 145,
        },
      },
    },
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async getStatistics() {
    const statistics = await this.usersService.getUserStatistics();
    return {
      statusCode: HttpStatus.OK,
      message: 'Statistics retrieved successfully',
      data: statistics,
    };
  }

  @Get(':id')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Get user by ID',
    description:
      'Retrieves a specific user by their unique identifier. Only administrators can access this endpoint.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the user',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiOkResponse({
    description: 'User retrieved successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'User retrieved successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          roles: [
            {
              _id: '64a7b8c9d1e2f3g4h5i6j7k9',
              name: 'user',
              displayName: 'User',
            },
          ],
          isActive: true,
          emailVerified: true,
          createdAt: '2024-01-20T10:30:00.000Z',
          updatedAt: '2024-01-20T10:30:00.000Z',
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  @ApiBadRequestResponse({ description: 'Invalid user ID format' })
  async findById(@Param('id') id: string) {
    const user = await this.usersService.findById(id);
    return {
      statusCode: HttpStatus.OK,
      message: 'User retrieved successfully',
      data: user,
    };
  }

  @Put(':id')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Update user',
    description:
      'Updates an existing user with new information. Only administrators can update users.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the user to update',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiBody({ type: UpdateUserDto, description: 'Updated user data' })
  @ApiOkResponse({
    description: 'User updated successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'User updated successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Smith',
          email: 'john.smith@example.com',
          roles: [
            {
              _id: '64a7b8c9d1e2f3g4h5i6j7k9',
              name: 'admin',
              displayName: 'Administrator',
            },
          ],
          isActive: true,
          emailVerified: true,
          updatedAt: '2024-01-20T15:45:00.000Z',
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiConflictResponse({ description: 'Email already exists' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  @ApiBadRequestResponse({
    description: 'Invalid user data, ID format, or role IDs',
  })
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    const user = await this.usersService.update(id, updateUserDto);
    return {
      statusCode: HttpStatus.OK,
      message: 'User updated successfully',
      data: user,
    };
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Delete user',
    description:
      'Soft deletes a user from the system (sets isActive to false). Only administrators can delete users.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the user to delete',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiOkResponse({
    description: 'User deleted successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'User deleted successfully',
      },
    },
  })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiBadRequestResponse({
    description: 'Cannot delete admin users or invalid ID format',
  })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async remove(@Param('id') id: string) {
    await this.usersService.remove(id);
    return {
      statusCode: HttpStatus.OK,
      message: 'User deleted successfully',
    };
  }

  @Put(':id/roles')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Assign roles to user',
    description:
      'Assigns one or more roles to a user. Only administrators can assign roles.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the user',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiBody({ type: AssignUserRolesDto, description: 'Role IDs to assign' })
  @ApiOkResponse({
    description: 'Roles assigned successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Roles assigned successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          roles: [
            {
              _id: '64a7b8c9d1e2f3g4h5i6j7k9',
              name: 'admin',
              displayName: 'Administrator',
            },
            {
              _id: '64a7b8c9d1e2f3g4h5i6j7l0',
              name: 'user',
              displayName: 'User',
            },
          ],
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'User or role not found' })
  @ApiBadRequestResponse({ description: 'Invalid user ID or role ID format' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async assignRoles(
    @Param('id') id: string,
    @Body() assignRolesDto: AssignUserRolesDto,
  ) {
    const user = await this.usersService.assignRoles(
      id,
      assignRolesDto.roleIds,
    );
    return {
      statusCode: HttpStatus.OK,
      message: 'Roles assigned successfully',
      data: user,
    };
  }

  @Put(':id/lock')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Lock user account',
    description:
      'Locks a user account for security reasons. Only administrators can lock accounts.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the user to lock',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiOkResponse({
    description: 'Account locked successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Account locked successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          isLocked: true,
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async lockAccount(@Param('id') id: string) {
    const user = await this.usersService.lockAccount(id);
    return {
      statusCode: HttpStatus.OK,
      message: 'Account locked successfully',
      data: user,
    };
  }

  @Put(':id/unlock')
  @UseGuards(RolesGuard)
  @RequireRoles('admin')
  @ApiOperation({
    summary: 'Unlock user account',
    description:
      'Unlocks a previously locked user account. Only administrators can unlock accounts.',
  })
  @ApiParam({
    name: 'id',
    description: 'MongoDB ObjectId of the user to unlock',
    example: '64a7b8c9d1e2f3g4h5i6j7k8',
  })
  @ApiOkResponse({
    description: 'Account unlocked successfully',
    schema: {
      example: {
        statusCode: 200,
        message: 'Account unlocked successfully',
        data: {
          _id: '64a7b8c9d1e2f3g4h5i6j7k8',
          fullName: 'John Doe',
          email: 'john.doe@example.com',
          isLocked: false,
        },
      },
    },
  })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiForbiddenResponse({ description: 'Forbidden - Admin access required' })
  async unlockAccount(@Param('id') id: string) {
    const user = await this.usersService.unlockAccount(id);
    return {
      statusCode: HttpStatus.OK,
      message: 'Account unlocked successfully',
      data: user,
    };
  }

  @Post('hotmart-webhook')
  @HttpCode(200)
  async handleWebhook(@Body() payload: any) {
    console.log('weeee', payload);
    await this.usersService.processHotmartPayment(payload);
    return { status: 'ok' };
  }
}
