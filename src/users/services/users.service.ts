import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { Types } from 'mongoose';
import { UsersRepository } from '@users/repositories/users.repository';
import { RolesService } from '@roles/services/roles.service';
import { CreateUserDto } from '@users/dtos/create-user.dto';
import { UpdateUserDto } from '@users/dtos/update-user.dto';
import { UserDocument } from '@users/schemas/user.schema';
import { PopulatedRole } from '@users/interfaces/role.interface';

@Injectable()
export class UsersService {
  constructor(
    private readonly usersRepository: UsersRepository,
    private readonly rolesService: RolesService,
  ) {}
  private readonly logger = new Logger(UsersService.name);

  /**
   * Create a new user
   * @param createUserDto User creation data
   * @returns Created user document
   */
  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    const existingUser = await this.usersRepository.findByEmail(
      createUserDto.email,
    );
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    if (createUserDto.googleId) {
      const existingGoogleUser = await this.usersRepository.findByGoogleId(
        createUserDto.googleId,
      );
      if (existingGoogleUser) {
        throw new ConflictException('User with this Google ID already exists');
      }
    }

    if (!createUserDto.roles || createUserDto.roles.length === 0) {
      try {
        const defaultRole = await this.rolesService.getDefaultRole();
        if (defaultRole) {
          createUserDto.roles = [String(defaultRole._id as Types.ObjectId)];
        }
      } catch {
        throw new InternalServerErrorException('Failed to get default role');
      }
    }

    if (createUserDto.roles && createUserDto.roles.length > 0) {
      await this.validateRoleIds(createUserDto.roles);
    }

    return this.usersRepository.create(createUserDto);
  }

  /**
   * Find user by ID
   * @param id User ID
   * @returns User document
   * @throws NotFoundException if user not found
   */
  async findById(id: string | Types.ObjectId): Promise<UserDocument> {
    const user = await this.usersRepository.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Find user by email
   * @param email User email
   * @returns User document
   * @throws NotFoundException if user not found
   */
  async findByEmail(email: string): Promise<UserDocument> {
    const user = await this.usersRepository.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Find user by Google ID
   * @param googleId Google OAuth ID
   * @returns User document
   * @throws NotFoundException if user not found
   */
  async findByGoogleId(googleId: string): Promise<UserDocument> {
    const user = await this.usersRepository.findByGoogleId(googleId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Find all users with pagination and filtering
   * @param page Page number (default: 1)
   * @param limit Number of items per page (default: 10)
   * @param search Search term for name or email
   * @param isActive Filter by active status
   * @param emailVerified Filter by email verification status
   * @returns Paginated users result
   */
  async findAll(
    page: number = 1,
    limit: number = 10,
    search?: string,
    isActive?: boolean,
    emailVerified?: boolean,
  ): Promise<{
    users: UserDocument[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    const result = await this.usersRepository.findAll(
      page,
      limit,
      search,
      isActive,
      emailVerified,
    );
    const totalPages = Math.ceil(result.total / limit);

    return {
      ...result,
      page,
      totalPages,
    };
  }

  /**
   * Find all users without pagination
   * @param isActive Filter by active status
   * @param emailVerified Filter by email verification status
   * @returns Array of user documents
   */
  async findAllUsers(
    isActive?: boolean,
    emailVerified?: boolean,
  ): Promise<UserDocument[]> {
    const filter: Record<string, any> = {};

    if (isActive !== undefined) {
      filter.isActive = isActive;
    }

    if (emailVerified !== undefined) {
      filter.emailVerified = emailVerified;
    }

    return this.usersRepository.findAllUsers(filter);
  }

  /**
   * Find active users with pagination
   * @param page Page number (default: 1)
   * @param limit Number of items per page (default: 10)
   * @returns Active users result
   */
  async findActiveUsers(
    page: number = 1,
    limit: number = 10,
  ): Promise<{
    users: UserDocument[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    const result = await this.usersRepository.findActiveUsers(page, limit);
    const totalPages = Math.ceil(result.total / limit);

    return {
      ...result,
      page,
      totalPages,
    };
  }

  /**
   * Search users by name or email
   * @param searchTerm Search term
   * @param page Page number (default: 1)
   * @param limit Number of items per page (default: 10)
   * @returns Search results
   */
  async searchUsers(
    searchTerm: string,
    page: number = 1,
    limit: number = 10,
  ): Promise<{
    users: UserDocument[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    const result = await this.usersRepository.searchUsers(
      searchTerm,
      page,
      limit,
    );
    const totalPages = Math.ceil(result.total / limit);

    return {
      ...result,
      page,
      totalPages,
    };
  }

  /**
   * Update user
   * @param id User ID
   * @param updateUserDto Updated user data
   * @returns Updated user document
   */
  async update(
    id: string | Types.ObjectId,
    updateUserDto: UpdateUserDto,
  ): Promise<UserDocument> {
    const existingUser = await this.findById(id);

    // Check if email is being changed and if it's already taken
    if (updateUserDto.email && updateUserDto.email !== existingUser.email) {
      const emailExists = await this.usersRepository.existsByEmail(
        updateUserDto.email,
      );
      if (emailExists) {
        throw new ConflictException('Email already exists');
      }
    }

    // Validate role IDs if provided
    if (updateUserDto.roles && updateUserDto.roles.length > 0) {
      await this.validateRoleIds(updateUserDto.roles);
    }

    const updatedUser = await this.usersRepository.updateById(
      id,
      updateUserDto,
    );
    if (!updatedUser) {
      throw new NotFoundException('User not found');
    }

    return updatedUser;
  }

  /**
   * Remove user (soft delete)
   * @param id User ID
   */
  async remove(id: string | Types.ObjectId): Promise<void> {
    const user = await this.findById(id);

    // Prevent deletion of admin users (optional business rule)
    const isAdmin = await this.hasRole(user._id as Types.ObjectId, 'admin');
    if (isAdmin) {
      throw new BadRequestException('Cannot delete admin users');
    }

    const deleted = await this.usersRepository.softDelete(id);
    if (!deleted) {
      throw new NotFoundException('User not found');
    }
  }

  /**
   * Assign roles to user
   * @param userId User ID
   * @param roleIds Array of role IDs
   * @returns Updated user document
   */
  async assignRoles(
    userId: string | Types.ObjectId,
    roleIds: string[],
  ): Promise<UserDocument> {
    await this.findById(userId); // Ensure user exists
    await this.validateRoleIds(roleIds);

    const updatedUser = await this.usersRepository.updateRoles(userId, roleIds);
    if (!updatedUser) {
      throw new NotFoundException('User not found');
    }

    return updatedUser;
  }

  /**
   * Update user last login timestamp
   * @param id User ID
   * @returns Updated user document
   */
  async updateLastLogin(id: string | Types.ObjectId): Promise<UserDocument> {
    const user = await this.usersRepository.updateLastLogin(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Update user password
   * @param id User ID
   * @param hashedPassword New hashed password
   * @returns Updated user document
   */
  async updatePassword(
    id: string | Types.ObjectId,
    hashedPassword: string,
  ): Promise<UserDocument> {
    const user = await this.usersRepository.updatePassword(id, hashedPassword);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Verify user email
   * @param id User ID
   * @returns Updated user document
   */
  async verifyEmail(id: string | Types.ObjectId): Promise<UserDocument> {
    const user = await this.usersRepository.verifyEmail(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Lock user account
   * @param id User ID
   * @returns Updated user document
   */
  async lockAccount(id: string | Types.ObjectId): Promise<UserDocument> {
    const user = await this.usersRepository.lockAccount(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Unlock user account
   * @param id User ID
   * @returns Updated user document
   */
  async unlockAccount(id: string | Types.ObjectId): Promise<UserDocument> {
    const user = await this.usersRepository.unlockAccount(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Check if user has a specific role
   * @param userId User ID
   * @param roleName Role name to check
   * @returns Boolean indicating if user has the role
   */
  async hasRole(
    userId: string | Types.ObjectId,
    roleName: string,
  ): Promise<boolean> {
    const user = await this.findById(userId);

    // Check roles array (populated)
    if (user.roles && Array.isArray(user.roles)) {
      return user.roles.some((role) => {
        // Handle both populated and non-populated roles
        if (typeof role === 'object' && 'name' in role) {
          return (role as PopulatedRole).name === roleName;
        }
        return false;
      });
    }

    return false;
  }

  /**
   * Check if user has any of the specified roles
   * @param userId User ID
   * @param roleNames Array of role names to check
   * @returns Boolean indicating if user has any of the roles
   */
  async hasAnyRole(
    userId: string | Types.ObjectId,
    roleNames: string[],
  ): Promise<boolean> {
    const promises = roleNames.map((roleName) =>
      this.hasRole(userId, roleName),
    );
    const results = await Promise.all(promises);
    return results.some(Boolean);
  }

  /**
   * Get user roles
   * @param userId User ID
   * @returns Array of role names
   */
  async getUserRoles(userId: string | Types.ObjectId): Promise<string[]> {
    const user = await this.findById(userId);

    if (user.roles && Array.isArray(user.roles)) {
      return user.roles
        .filter(
          (role): role is PopulatedRole =>
            typeof role === 'object' && 'name' in role,
        )
        .map((role) => role.name);
    }

    return [];
  }

  /**
   * Get user's primary role
   * @param userId User ID
   * @returns Primary role name
   */
  async getPrimaryRole(userId: string | Types.ObjectId): Promise<string> {
    const user = await this.findById(userId);

    if (user.roles && user.roles.length > 0) {
      const firstRole = user.roles[0];
      if (typeof firstRole === 'object' && 'name' in firstRole) {
        return (firstRole as PopulatedRole).name;
      }
    }

    return 'user'; // Default role
  }

  /**
   * Get user statistics
   * @returns User statistics object
   */
  async getUserStatistics(): Promise<{
    total: number;
    active: number;
    inactive: number;
    verified: number;
    unverified: number;
    locked: number;
    withRoles: number;
  }> {
    return this.usersRepository.getStatistics();
  }

  /**
   * Validate that all role IDs exist
   * @param roleIds Array of role IDs to validate
   * @throws BadRequestException if any role ID is invalid
   */
  private async validateRoleIds(roleIds: string[]): Promise<void> {
    const validationPromises = roleIds.map((roleId) =>
      this.rolesService.findById(roleId),
    );
    try {
      await Promise.all(validationPromises);
    } catch {
      throw new BadRequestException('One or more role IDs are invalid');
    }
  }

  async processHotmartPayment(payload: any): Promise<void> {
    const { event, data } = payload;
    const email = data.buyer.email.toLowerCase();
    // const transactionId = data.transaction_id;
    // const subscriberCode = data.subscriber_code;
    const user = await this.usersRepository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(`User not found with email: ${email}`);
    }

    switch (event) {
      case 'PURCHASE_COMPLETE':
        await this.handlePurchaseComplete(user, data);
        break;
      case 'PURCHASE_CANCELED':
      case 'PURCHASE_REFUNDED':
      case 'SUBSCRIPTION_CANCELED':
        await this.handlePurchaseCanceled(user);
        break;
      default:
        this.logger.warn(`Unhandled Hotmart event: ${event}`);
    }
  }

  private async handlePurchaseComplete(user: any, data: any): Promise<void> {
    const updateData = {
      isPremium: true,
      subscriptionStatus: 'active',
      hotmartTransactionId: `${data.transaction_id}`,
      hotmartSubscriberCode: `${data.subscriber_code}`,
      paymentProvider: 'hotmart',
      lastPaymentDate: new Date(),
      paymentAmount: Math.round(data.purchase.price * 100),
      paymentCurrency: `${data.purchase.currency_code}`,
      subscriptionStartDate: new Date(),
    };

    // Set expiry date if it's a subscription with next charge date
    // if (data.subscription?.date_next_charge) {
    //   updateData.subscriptionExpiryDate = new Date(data.subscription.date_next_charge);
    //   updateData.autoRenewal = true;
    // }

    await this.usersRepository.findByIdAndUpdate(user._id, updateData);
    this.logger.log(`User subscription activated: ${user.email}`);
  }

  private async handlePurchaseCanceled(user: any): Promise<void> {
    const updateData = {
      isPremium: false,
      subscriptionStatus: 'cancelled',
      autoRenewal: false,
    };
    await this.usersRepository.findByIdAndUpdate(user._id, updateData);
    this.logger.log(`User subscription canceled: ${user.email}`);
  }
}
