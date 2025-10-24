/**
 * JWT blacklist utility.
 * Supports both in-memory storage and custom storage services.
 */

export interface BlacklistStorage {
  add: (token: string, expiresAt?: Date) => Promise<void> | void;
  has: (token: string) => Promise<boolean> | boolean;
  remove: (token: string) => Promise<void> | void;
  clear: () => Promise<void> | void;
}

const tokenBlacklist = new Set<string>();
let blacklistStorage: BlacklistStorage | null = null;

/**
 * Set a custom storage service for token blacklist.
 * @param storage Custom storage service implementing BlacklistStorage
 */
export const setBlacklistStorage = (storage: BlacklistStorage): void => {
  blacklistStorage = storage;
};

/**
 * Add a token to the blacklist
 * @param token JWT token string
 * @param expiresAt Optional expiry date of token
 */
export const addToBlacklist = async (
  token: string,
  expiresAt?: Date
): Promise<void> => {
  if (blacklistStorage) {
    await blacklistStorage.add(token, expiresAt);
  } else {
    tokenBlacklist.add(token);
  }
};

/**
 * Check if a token exists in the blacklist
 * @param token JWT token string
 * @returns true if token is blacklisted
 */
export const isInBlacklist = async (token: string): Promise<boolean> => {
  if (blacklistStorage) {
    return await blacklistStorage.has(token);
  }
  return tokenBlacklist.has(token);
};

/**
 * Remove a token from the blacklist
 * @param token JWT token string
 */
export const removeFromBlacklist = async (token: string): Promise<void> => {
  if (blacklistStorage) {
    await blacklistStorage.remove(token);
  } else {
    tokenBlacklist.delete(token);
  }
};

/**
 * Clear all tokens from the blacklist
 */
export const clearBlacklist = async (): Promise<void> => {
  if (blacklistStorage) {
    await blacklistStorage.clear();
  } else {
    tokenBlacklist.clear();
  }
};
