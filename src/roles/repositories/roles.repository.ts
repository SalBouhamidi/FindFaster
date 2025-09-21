import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types, FilterQuery } from 'mongoose';
import { Role, RoleDocument } from '../schemas/role.schema';
import { CreateRoleDto } from '../dtos/create-role.dto';
import { UpdateRoleDto } from '../dtos/update-role.dto';

@Injectable()
export class RolesRepository {
  constructor(
    @InjectModel(Role.name) private readonly roleModel: Model<RoleDocument>,
  ) {}

  async create(createRoleDto: CreateRoleDto): Promise<RoleDocument> {
    const createdRole = new this.roleModel(createRoleDto);
    return createdRole.save();
  }

  async findById(id: string | Types.ObjectId): Promise<RoleDocument | null> {
    return this.roleModel.findById(id).exec();
  }

  async findByName(name: string): Promise<RoleDocument | null> {
    return this.roleModel.findOne({ name: name.toLowerCase() }).exec();
  }

  async findAll(
    filter: FilterQuery<RoleDocument> = {},
  ): Promise<RoleDocument[]> {
    return this.roleModel.find(filter).sort({ name: 1 }).exec();
  }

  async updateById(
    id: string | Types.ObjectId,
    updateRoleDto: UpdateRoleDto,
  ): Promise<RoleDocument | null> {
    return this.roleModel
      .findByIdAndUpdate(id, updateRoleDto, { new: true })
      .exec();
  }

  async deleteById(id: string | Types.ObjectId): Promise<boolean> {
    const result = await this.roleModel.deleteOne({ _id: id }).exec();
    return result.deletedCount > 0;
  }

  async findDefaultRole(): Promise<RoleDocument | null> {
    return this.roleModel.findOne({ isDefault: true, isActive: true }).exec();
  }

  async existsByName(name: string): Promise<boolean> {
    const count = await this.roleModel
      .countDocuments({ name: name.toLowerCase() })
      .exec();
    return count > 0;
  }

  async count(filter: FilterQuery<RoleDocument> = {}): Promise<number> {
    return this.roleModel.countDocuments(filter).exec();
  }

  async findActiveRoles(): Promise<RoleDocument[]> {
    return this.findAll({ isActive: true });
  }

  async setAsDefault(roleName: string): Promise<RoleDocument | null> {
    await this.roleModel.updateMany({ isDefault: true }, { isDefault: false });

    return this.roleModel
      .findOneAndUpdate({ name: roleName }, { isDefault: true }, { new: true })
      .exec();
  }

  async getStatistics(): Promise<{
    total: number;
    active: number;
    inactive: number;
    userRoles: number;
    adminRoles: number;
  }> {
    const [total, active, userRoles, adminRoles] = await Promise.all([
      this.count(),
      this.count({ isActive: true }),
      this.count({ name: 'user' }),
      this.count({ name: 'admin' }),
    ]);

    return {
      total,
      active,
      inactive: total - active,
      userRoles,
      adminRoles,
    };
  }
}
