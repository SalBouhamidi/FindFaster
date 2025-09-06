import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';

export type RoleDocument = Role & Document;

@Schema({
  timestamps: true,
  collection: 'roles',
})
export class Role {
  @ApiProperty({
    description: 'Unique role name identifier',
    enum: ['user', 'admin'],
    example: 'user',
  })
  @Prop({
    required: true,
    unique: true,
    enum: ['user', 'admin'],
    index: true,
  })
  name: string;

  @ApiProperty({
    description: 'Human-readable display name for the role',
    example: 'Standard User',
  })
  @Prop({
    required: true,
    trim: true,
  })
  displayName: string;

  @ApiProperty({
    description: 'Whether the role is currently active',
    example: true,
    default: true,
  })
  @Prop({
    required: true,
    default: true,
  })
  isActive: boolean;

  @ApiProperty({
    description: 'Whether this is the default role assigned to new users',
    example: false,
    default: false,
  })
  @Prop({
    required: true,
    default: false,
  })
  isDefault: boolean;

  @ApiProperty({
    description: 'Role creation timestamp',
    example: '2024-01-20T10:30:00.000Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'Role last update timestamp',
    example: '2024-01-20T10:30:00.000Z',
  })
  updatedAt: Date;
}

export const RoleSchema = SchemaFactory.createForClass(Role);
