import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types, Document } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';
import { PopulatedRole } from '@users/interfaces/authenticated-user.interface';

export type UserDocument = User & Document;

export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

export enum SubscriptionStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  EXPIRED = 'expired',
  CANCELLED = 'cancelled',
  PENDING = 'pending',
}

export enum PaymentProvider {
  HOTMART = 'hotmart',
  STRIPE = 'stripe',
}

@Schema({
  timestamps: true,
  collection: 'users',
})
export class User {
  @ApiProperty({
    description: "User's full name",
    example: 'John Doe',
  })
  @Prop({ required: true, trim: true })
  fullName: string;

  @ApiProperty({
    description: "User's email address",
    example: 'john.doe@example.com',
  })
  @Prop({
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
  })
  email: string;

  @ApiProperty({
    description: 'Hashed password - nullable for OAuth users',
    required: false,
  })
  @Prop({ required: false })
  password?: string;

  @ApiProperty({
    description: 'Google OAuth ID - nullable for traditional auth users',
    required: false,
  })
  @Prop({ required: false, sparse: true })
  googleId?: string;

  @ApiProperty({
    description: "User's profile picture URL",
    example: 'https://example.com/avatar.jpg',
    required: false,
  })
  @Prop({ required: false })
  profilePicture?: string;

  @ApiProperty({
    description: 'Assigned roles for RBAC',
    type: [String],
    example: ['64a7b8c9d1e2f3g4h5i6j7k8'],
  })
  @Prop({
    type: [{ type: Types.ObjectId, ref: 'Role' }],
    default: [],
  })
  roles: (Types.ObjectId | PopulatedRole)[];

  @ApiProperty({
    description: 'Email verification status',
    example: true,
  })
  @Prop({ required: true, default: false })
  emailVerified: boolean;

  @ApiProperty({
    description: 'Account active status',
    example: true,
  })
  @Prop({ required: true, default: true })
  isActive: boolean;

  @ApiProperty({
    description: 'Account locked status for security',
    example: false,
  })
  @Prop({ required: true, default: false })
  isLocked: boolean;

  @ApiProperty({
    description: 'User role for access control',
    enum: UserRole,
    example: UserRole.USER,
  })
  @Prop({ required: true, enum: UserRole, default: UserRole.USER })
  role: UserRole;

  @ApiProperty({
    description: 'Terms of service acceptance',
    example: true,
  })
  @Prop({ required: true, default: false })
  termsAccepted: boolean;

  @ApiProperty({
    description: 'Subscribe to platform updates',
    example: false,
  })
  @Prop({ required: true, default: false })
  subscribeUpdates: boolean;

  @ApiProperty({
    description: 'Failed login attempts count',
    example: 0,
  })
  @Prop({ required: true, default: 0 })
  failedLoginAttempts: number;

  @ApiProperty({
    description: 'Account lock expiry timestamp',
    required: false,
  })
  @Prop({ required: false })
  lockExpiresAt?: Date;

  @ApiProperty({
    description: 'Last successful login timestamp',
    example: '2024-01-20T10:30:00.000Z',
    required: false,
  })
  @Prop({ required: false })
  lastLoginAt?: Date;

  @ApiProperty({
    description: 'Last login IP address',
    example: '192.168.1.1',
    required: false,
  })
  @Prop({ required: false })
  lastLoginIp?: string;

  @ApiProperty({
    description: 'Password changed at timestamp',
    required: false,
  })
  @Prop({ required: false })
  passwordChangedAt?: Date;

  @ApiProperty({
    description: 'Email verification token',
    required: false,
  })
  @Prop({ required: false })
  emailVerificationToken?: string;

  @ApiProperty({
    description: 'Email verification token expiry',
    required: false,
  })
  @Prop({ required: false })
  emailVerificationExpires?: Date;

  @ApiProperty({
    description: 'Password reset token',
    required: false,
  })
  @Prop({ required: false })
  passwordResetToken?: string;

  @ApiProperty({
    description: 'Password reset token expiry',
    required: false,
  })
  @Prop({ required: false })
  passwordResetExpires?: Date;

  @ApiProperty({
    description: 'Two-factor authentication enabled',
    example: false,
  })
  @Prop({ required: true, default: false })
  twoFactorEnabled: boolean;

  @ApiProperty({
    description: 'Two-factor authentication secret',
    required: false,
  })
  @Prop({ required: false })
  twoFactorSecret?: string;

  @ApiProperty({
    description: 'User subscription status',
    enum: SubscriptionStatus,
    example: SubscriptionStatus.INACTIVE,
  })
  @Prop({
    required: true,
    enum: SubscriptionStatus,
    default: SubscriptionStatus.INACTIVE,
  })
  subscriptionStatus: SubscriptionStatus;

  @ApiProperty({
    description: 'Is user premium/paid subscriber',
    example: false,
  })
  @Prop({
    required: true,
    default: false,
  })
  isPremium: boolean;

  @ApiProperty({
    description: 'Subscription start date',
    example: '2024-01-20T10:30:00.000Z',
    required: false,
  })
  @Prop({
    required: false,
  })
  subscriptionStartDate?: Date;

  @ApiProperty({
    description: 'Subscription expiry date',
    example: '2024-12-20T10:30:00.000Z',
    required: false,
  })
  @Prop({
    required: false,
  })
  subscriptionExpiryDate?: Date;

  @ApiProperty({
    description: 'Hotmart transaction ID',
    example: 'HP12345678901',
    required: false,
  })
  @Prop({ required: false, index: true })
  hotmartTransactionId?: string;

  @ApiProperty({
    description: 'Hotmart subscriber code',
    example: 'SC123456789',
    required: false,
  })
  @Prop({ required: false, index: true })
  hotmartSubscriberCode?: string;

  @ApiProperty({
    description: 'Payment provider used',
    enum: PaymentProvider,
    example: PaymentProvider.HOTMART,
    required: false,
  })
  @Prop({
    required: false,
    enum: PaymentProvider,
    default: PaymentProvider.HOTMART,
  })
  paymentProvider?: PaymentProvider;

  @ApiProperty({
    description: 'Last payment date',
    example: '2024-01-20T10:30:00.000Z',
    required: false,
  })
  @Prop({ required: false })
  lastPaymentDate?: Date;

  @ApiProperty({
    description: 'Payment amount in cents',
    example: 2999,
    required: false,
  })
  @Prop({ required: false })
  paymentAmount?: number;

  @ApiProperty({
    description: 'Payment currency',
    example: 'USD',
    required: false,
  })
  @Prop({ required: false })
  paymentCurrency?: string;

  @ApiProperty({
    description: 'Auto-renewal enabled',
    example: true,
    required: false,
  })
  @Prop({ required: false, default: false })
  autoRenewal?: boolean;

  @ApiProperty({
    description: 'User creation timestamp',
    example: '2024-01-20T10:30:00.000Z',
  })
  createdAt: Date;

  @ApiProperty({
    description: 'User last update timestamp',
    example: '2024-01-20T10:30:00.000Z',
  })
  updatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.index({ emailVerificationToken: 1 }, { sparse: true });
UserSchema.index({ passwordResetToken: 1 }, { sparse: true });
UserSchema.index({ isActive: 1, isLocked: 1 });
UserSchema.index({ createdAt: 1 });
UserSchema.index({ lastLoginAt: -1 });
UserSchema.index({ isPremium: 1 });
UserSchema.index({ hotmartTransactionId: 1 }, { sparse: true });
UserSchema.index({ hotmartSubscriberCode: 1 }, { sparse: true });
UserSchema.index({ subscriptionStatus: 1 });
UserSchema.index({ subscriptionExpiryDate: 1 });

// Add security hooks
UserSchema.pre('save', function (next) {
  // Update passwordChangedAt when password is modified
  if (this.isModified('password') && !this.isNew) {
    this.passwordChangedAt = new Date();
  }
  next();
});

// Add virtual for account status
UserSchema.virtual('accountStatus').get(function () {
  if (!this.isActive) return 'inactive';
  if (this.isLocked) return 'locked';
  if (!this.emailVerified) return 'unverified';
  return 'active';
});

// Ensure virtual fields are included in JSON output
UserSchema.set('toJSON', { virtuals: true });
UserSchema.set('toObject', { virtuals: true });

// Add a virtual for checking if subscription is active
UserSchema.virtual('isSubscriptionActive').get(function () {
  if (!this.isPremium) return false;
  if (this.subscriptionStatus !== SubscriptionStatus.ACTIVE) return false;
  if (this.subscriptionExpiryDate && this.subscriptionExpiryDate < new Date())
    return false;
  return true;
});
