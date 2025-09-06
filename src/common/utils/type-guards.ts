/**
 * Type guards and utility functions for better type safety
 */

/**
 * Type guard to check if a value is an Error
 */
export function isError(error: unknown): error is Error {
  return error instanceof Error;
}

/**
 * Type guard to check if an error has a message property
 */
export function hasMessage(error: unknown): error is { message: string } {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as { message: unknown }).message === 'string'
  );
}

/**
 * Safely get error message with fallback
 */
export function getErrorMessage(error: unknown): string {
  if (isError(error)) {
    return error.message;
  }

  if (hasMessage(error)) {
    const errorWithMessage = error as { message: string };
    return errorWithMessage.message;
  }

  if (typeof error === 'string') {
    return error;
  }

  return 'An unknown error occurred';
}

/**
 * Type guard for checking if value is a string
 */
export function isString(value: unknown): value is string {
  return typeof value === 'string';
}

/**
 * Type guard for checking if value is an object
 */
export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Safely convert MongoDB ObjectId to string
 */
export function objectIdToString(id: unknown): string {
  if (typeof id === 'object' && id !== null && 'toString' in id) {
    return (id as { toString(): string }).toString();
  }

  if (typeof id === 'string') {
    return id;
  }

  throw new Error('Invalid ObjectId type');
}

/**
 * Type guard for request body validation
 */
export function hasProperty<T extends string>(
  obj: unknown,
  prop: T,
): obj is Record<T, unknown> {
  return isObject(obj) && prop in obj;
}

/**
 * Safe property access with type checking
 */
export function getProperty<T>(obj: unknown, prop: string, defaultValue: T): T {
  if (isObject(obj) && prop in obj) {
    const value = obj[prop];
    if (typeof value === typeof defaultValue) {
      return value as T;
    }
  }
  return defaultValue;
}
