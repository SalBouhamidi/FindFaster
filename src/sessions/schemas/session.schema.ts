import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type SessionDocument = Session & Document;

/**
 * Device information interface for sessions
 */
@Schema({ _id: false })
export class DeviceInfo {
  @Prop({
    required: true,
    enum: ['desktop', 'mobile', 'tablet', 'unknown'],
    default: 'unknown',
  })
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';

  @Prop({ required: true, default: 'Unknown' })
  browser: string;

  @Prop({ required: true, default: 'Unknown' })
  os: string;

  @Prop({ required: true, default: 'unknown' })
  deviceId: string;

  @Prop({ required: true, default: false })
  isTrusted: boolean;

  @Prop({ required: false })
  browserVersion?: string;

  @Prop({ required: false })
  osVersion?: string;

  @Prop({ required: false })
  screenResolution?: string;

  @Prop({ required: false })
  timezone?: string;
}

/**
 * Session schema following Single Responsibility Principle
 * Each session represents a user's active connection from a specific device
 */
@Schema({
  timestamps: true,
  collection: 'sessions',
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})
export class Session {
  @Prop({ required: true, type: Types.ObjectId, ref: 'User', index: true })
  userId: Types.ObjectId;

  @Prop({ required: true, type: Types.ObjectId, ref: 'Token', index: true })
  tokenId: Types.ObjectId;

  @Prop({ required: true, type: DeviceInfo })
  deviceInfo: DeviceInfo;

  @Prop({ required: true, index: true })
  ipAddress: string;

  @Prop({ required: true })
  userAgent: string;

  @Prop({ required: true, default: Date.now, index: true })
  lastUsedAt: Date;

  @Prop({ required: true, default: true })
  isActive: boolean;

  @Prop({ required: false, type: Object })
  location?: {
    country?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };

  @Prop({ required: false, type: Object })
  securityInfo?: {
    isSuspicious: boolean;
    riskScore: number;
    flags: string[];
  };

  @Prop({ required: false, type: Object })
  metadata?: {
    appVersion?: string;
    platform?: string;
    language?: string;
    referrer?: string;
  };

  // Timestamps
  createdAt: Date;
  updatedAt: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);

// Performance indexes
SessionSchema.index({ userId: 1, isActive: 1 });
SessionSchema.index({ userId: 1, createdAt: 1 });
SessionSchema.index({ userId: 1, lastUsedAt: 1 });
SessionSchema.index({ isActive: 1, lastUsedAt: 1 });
SessionSchema.index({ 'deviceInfo.deviceType': 1 });
SessionSchema.index({ ipAddress: 1 });

// Virtual for session duration
SessionSchema.virtual('duration').get(function () {
  return this.lastUsedAt.getTime() - this.createdAt.getTime();
});

// Virtual for session age
SessionSchema.virtual('age').get(function () {
  return Date.now() - this.createdAt.getTime();
});

// Pre-save middleware to update lastUsedAt
SessionSchema.pre('save', function (next) {
  if (this.isModified('lastUsedAt')) {
    this.lastUsedAt = new Date();
  }
  next();
});
