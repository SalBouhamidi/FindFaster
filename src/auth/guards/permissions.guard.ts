import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthenticatedUser } from '../interfaces/auth.interface';
import { RoleAssignmentService } from '../../roles/services/role-assignment.service';

/**
 * Permission-based access control guard
 * Checks if user has required permissions for accessing the route
 */
@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private roleAssignmentService: RoleAssignmentService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check for different permission decorators
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      'permissions',
      [context.getHandler(), context.getClass()],
    );

    const anyPermissions = this.reflector.getAllAndOverride<string[]>(
      'anyPermissions',
      [context.getHandler(), context.getClass()],
    );

    const allPermissions = this.reflector.getAllAndOverride<string[]>(
      'allPermissions',
      [context.getHandler(), context.getClass()],
    );

    // If no permissions are required, allow access
    if (!requiredPermissions && !anyPermissions && !allPermissions) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<{ user: AuthenticatedUser }>();
    const user: AuthenticatedUser = request.user;

    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    try {
      // Check standard permissions (AND logic by default)
      if (requiredPermissions?.length) {
        const hasAllPermissions =
          await this.roleAssignmentService.userHasAllPermissions(
            user.id,
            requiredPermissions,
          );
        if (!hasAllPermissions) {
          throw new ForbiddenException(
            `Access denied. Required permissions: ${requiredPermissions.join(', ')}`,
          );
        }
      }

      // Check any permissions (OR logic)
      if (anyPermissions?.length) {
        const hasAnyPermission =
          await this.roleAssignmentService.userHasAnyPermission(
            user.id,
            anyPermissions,
          );
        if (!hasAnyPermission) {
          throw new ForbiddenException(
            `Access denied. Required any of these permissions: ${anyPermissions.join(', ')}`,
          );
        }
      }

      // Check all permissions (AND logic)
      if (allPermissions?.length) {
        const hasAllPermissions =
          await this.roleAssignmentService.userHasAllPermissions(
            user.id,
            allPermissions,
          );
        if (!hasAllPermissions) {
          throw new ForbiddenException(
            `Access denied. Required all permissions: ${allPermissions.join(', ')}`,
          );
        }
      }

      return true;
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      // Log the error and deny access for any other errors
      console.error('Permission check error:', error);
      throw new ForbiddenException('Permission check failed');
    }
  }
}
