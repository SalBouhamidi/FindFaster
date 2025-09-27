import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types, FilterQuery } from 'mongoose';
import { User, UserDocument } from '../schemas/user.schema';
import { CreateUserDto } from '../dtos/create-user.dto';
import { UpdateUserDto } from '../dtos/update-user.dto';

@Injectable()
export class UsersRepository {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  /**
   * Create a new user
   * @param createUserDto User creation data
   * @returns Created user document
   */
  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    const userData: Record<string, any> = {
      ...createUserDto,
      emailVerified:
        createUserDto.emailVerified ?? (createUserDto.googleId ? true : false),
      isActive: createUserDto.isActive ?? true,
    };

    // Convert role IDs to ObjectIds if provided
    if (createUserDto.roles && createUserDto.roles.length > 0) {
      userData.roles = createUserDto.roles.map(
        (roleId) => new Types.ObjectId(roleId),
      );
    }

    const user = new this.userModel(userData);
    return user.save();
  }

  /**
   * Find user by ID
   * @param id User ID
   * @returns User document or null
   */
  async findById(id: string | Types.ObjectId): Promise<UserDocument | null> {
    return this.userModel.findById(id).populate('roles').exec();
  }

  /**
   * Find user by email
   * @param email User email
   * @returns User document or null
   */
  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel
      .findOne({ email: email.toLowerCase() })
      .populate('roles')
      .exec();
  }

  /**
   * Find user by Google ID
   * @param googleId Google OAuth ID
   * @returns User document or null
   */
  async findByGoogleId(googleId: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ googleId }).populate('roles').exec();
  }

  /**
   * Find all users with optional pagination and filtering
   * @param page Page number (default: 1)
   * @param limit Number of items per page (default: 10)
   * @param search Search term for name or email
   * @param isActive Filter by active status
   * @param emailVerified Filter by email verification status
   * @returns Users array and total count
   */
  async findAll(
    page: number = 1,
    limit: number = 10,
    search?: string,
    isActive?: boolean,
    emailVerified?: boolean,
  ): Promise<{ users: UserDocument[]; total: number }> {
    const skip = (page - 1) * limit;
    const filter: FilterQuery<UserDocument> = {};

    // Build filter conditions
    if (search) {
      filter.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }

    if (isActive !== undefined) {
      filter.isActive = isActive;
    }

    if (emailVerified !== undefined) {
      filter.emailVerified = emailVerified;
    }

    // Execute queries in parallel
    const [users, total] = await Promise.all([
      this.userModel
        .find(filter)
        .populate('roles')
        .skip(skip)
        .limit(limit)
        .sort({ createdAt: -1 })
        .exec(),
      this.userModel.countDocuments(filter).exec(),
    ]);

    return { users, total };
  }

  /**
   * Find all users without pagination
   * @param filter Optional MongoDB filter
   * @returns Array of user documents
   */
  async findAllUsers(
    filter: FilterQuery<UserDocument> = {},
  ): Promise<UserDocument[]> {
    return this.userModel
      .find(filter)
      .populate('roles')
      .sort({ createdAt: -1 })
      .exec();
  }

  /**
   * Find active users only
   * @param page Page number (default: 1)
   * @param limit Number of items per page (default: 10)
   * @returns Active users array and total count
   */
  async findActiveUsers(
    page: number = 1,
    limit: number = 10,
  ): Promise<{ users: UserDocument[]; total: number }> {
    return this.findAll(page, limit, undefined, true);
  }

  /**
   * Search users by name or email
   * @param searchTerm Search term
   * @param page Page number (default: 1)
   * @param limit Number of items per page (default: 10)
   * @returns Matching users array and total count
   */
  async searchUsers(
    searchTerm: string,
    page: number = 1,
    limit: number = 10,
  ): Promise<{ users: UserDocument[]; total: number }> {
    return this.findAll(page, limit, searchTerm);
  }

  /**
   * Update user by ID
   * @param id User ID
   * @param updateData Partial user data to update
   * @returns Updated user document or null
   */
  async updateById(
    id: string | Types.ObjectId,
    updateData: UpdateUserDto,
  ): Promise<UserDocument | null> {
    const updatePayload: Record<string, any> = { ...updateData };

    // Convert role IDs to ObjectIds if provided
    if (updateData.roles) {
      updatePayload.roles = updateData.roles.map(
        (roleId) => new Types.ObjectId(roleId),
      );
    }

    return this.userModel
      .findByIdAndUpdate(id, updatePayload, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Update user last login timestamp
   * @param id User ID
   * @returns Updated user document or null
   */
  async updateLastLogin(
    id: string | Types.ObjectId,
  ): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(id, { lastLoginAt: new Date() }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Update user password
   * @param id User ID
   * @param hashedPassword New hashed password
   * @returns Updated user document or null
   */
  async updatePassword(
    id: string | Types.ObjectId,
    hashedPassword: string,
  ): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(id, { password: hashedPassword }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Update user roles
   * @param id User ID
   * @param roleIds Array of role IDs
   * @returns Updated user document or null
   */
  async updateRoles(
    id: string | Types.ObjectId,
    roleIds: string[],
  ): Promise<UserDocument | null> {
    const objectIds = roleIds.map((roleId) => new Types.ObjectId(roleId));
    return this.userModel
      .findByIdAndUpdate(id, { roles: objectIds }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Verify user email
   * @param id User ID
   * @returns Updated user document or null
   */
  async verifyEmail(id: string | Types.ObjectId): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(id, { emailVerified: true }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Soft delete user (set isActive to false)
   * @param id User ID
   * @returns Updated user document or null
   */
  async softDelete(id: string | Types.ObjectId): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(id, { isActive: false }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Lock user account
   * @param id User ID
   * @returns Updated user document or null
   */
  async lockAccount(id: string | Types.ObjectId): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(id, { isLocked: true }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Unlock user account
   * @param id User ID
   * @returns Updated user document or null
   */
  async unlockAccount(
    id: string | Types.ObjectId,
  ): Promise<UserDocument | null> {
    return this.userModel
      .findByIdAndUpdate(id, { isLocked: false }, { new: true })
      .populate('roles')
      .exec();
  }

  /**
   * Check if user exists by email
   * @param email User email
   * @returns Boolean indicating existence
   */
  async existsByEmail(email: string): Promise<boolean> {
    const count = await this.userModel
      .countDocuments({ email: email.toLowerCase() })
      .exec();
    return count > 0;
  }

  /**
   * Check if user exists by Google ID
   * @param googleId Google OAuth ID
   * @returns Boolean indicating existence
   */
  async existsByGoogleId(googleId: string): Promise<boolean> {
    const count = await this.userModel.countDocuments({ googleId }).exec();
    return count > 0;
  }

  /**
   * Count documents with optional filter
   * @param filter MongoDB filter query
   * @returns Number of matching documents
   */
  async count(filter: FilterQuery<UserDocument> = {}): Promise<number> {
    return this.userModel.countDocuments(filter).exec();
  }

  async findByIdAndUpdate(id, updatedData): Promise<UserDocument | null> {
    const response = await this.userModel.findByIdAndUpdate(id, updatedData);
    return response;
  }

  /**
   * Get user statistics
   * @returns User statistics object
   */
  async getStatistics(): Promise<{
    total: number;
    active: number;
    inactive: number;
    verified: number;
    unverified: number;
    locked: number;
    withRoles: number;
  }> {
    const [total, active, verified, locked, withRoles] = await Promise.all([
      this.count(),
      this.count({ isActive: true }),
      this.count({ emailVerified: true }),
      this.count({ isLocked: true }),
      this.count({ roles: { $ne: [] } }),
    ]);

    return {
      total,
      active,
      inactive: total - active,
      verified,
      unverified: total - verified,
      locked,
      withRoles,
    };
  }
}
