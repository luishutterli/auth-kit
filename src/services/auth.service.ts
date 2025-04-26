import { AccountRepository } from "../db/repositories/account.repository";
import { OrganizationRepository } from "../db/repositories/organization.repository";
import { hashPassword, verifyPassword, validatePassword } from "../utils/password";
import { generateToken, verifyToken } from "../utils/jwt";

import type {
  JWTPayload,
  AuthResult,
  User,
  AuthKitConfig,
} from "@luishutterli/auth-kit-types";
import {
  AuthKitError,
  AuthenticationError,
  DatabaseError,
  NotFoundError,
} from "@luishutterli/auth-kit-types";

export class AuthService {
  private readonly accountRepo: AccountRepository;
  private readonly orgRepo: OrganizationRepository;
  private readonly config: AuthKitConfig;

  constructor(config: AuthKitConfig) {
    this.accountRepo = new AccountRepository();
    this.orgRepo = new OrganizationRepository();
    this.config = config;
  }

  async signup(
    email: string,
    password: string,
    name: string,
    surname: string,
  ): Promise<AuthResult> {
    try {
      const existingUser = await this.accountRepo.getAccountByEmail(email);
      if (existingUser) {
        throw new AuthenticationError("User with this email already exists");
      }

      if (this.config.passwordPolicy) {
        const validation = validatePassword(password, this.config.passwordPolicy);
        if (!validation.valid) {
          throw new AuthenticationError(
            validation.message ?? "Password does not meet policy requirements",
          );
        }
      }

      const compoundHash = hashPassword(password, this.config);

      const newAccount = await this.accountRepo.createAccount({
        accEmail: email,
        accName: name,
        accSurname: surname,
        accPasswordHash: compoundHash,
        accEmailVerified: false,
        accStatus: "active",
      });

      const user = this.accountRepo.mapAccountToUser(newAccount);

      return this.generateAuthResult(user);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new DatabaseError("Failed to create user account", error as Error);
    }
  }

  async login(
    email: string,
    password: string,
    ip: string,
    userAgent: string,
  ): Promise<AuthResult> {
    try {
      const account = await this.accountRepo.getAccountByEmail(email);
      if (!account?.accPasswordHash) {
        throw new AuthenticationError("Invalid email or password");
      }

      const isPasswordValid = verifyPassword(
        password,
        account.accPasswordHash,
        this.config,
      );
      if (!isPasswordValid) {
        await this.accountRepo.recordLoginAttempt(account.accId, ip, userAgent, false);
        throw new AuthenticationError("Invalid email or password");
      }

      await this.accountRepo.recordLoginAttempt(account.accId, ip, userAgent, true);

      const user = await this.enrichUserDataOrgs(
        this.accountRepo.mapAccountToUser(account),
      );

      // TODO: enrich user data with permissions

      return this.generateAuthResult(user);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new DatabaseError("Failed to authenticate user", error as Error);
    }
  }

  async refreshToken(refreshToken: string): Promise<AuthResult> {
    try {
      // TODO: Implement
      throw new NotFoundError("Not implemented", 500);
    } catch (error) {
      if (error instanceof AuthKitError) {
        throw error;
      }
      throw new DatabaseError("Failed to refresh token", error as Error);
    }
  }

  async validateToken(token: string): Promise<User | null> {
    try {
      const payload = verifyToken<JWTPayload>(token, this.config.jwtConfig);
      if (!payload) {
        return null;
      }

      const account = await this.accountRepo.getAccountById(payload.sub);
      if (!account || account.accJWTversion !== payload.ver) {
        return null;
      }

      return payload.user;
    } catch (error) {
      return null;
    }
  }

  async getUserInfo(userId: number): Promise<User | null> {
    try {
      const account = await this.accountRepo.getAccountById(userId);
      if (!account) {
        throw new NotFoundError("User", userId);
      }

      return this.enrichUserDataOrgs(this.accountRepo.mapAccountToUser(account));
    } catch (error) {
      if (error instanceof NotFoundError) {
        throw error;
      }
      throw new DatabaseError("Failed to retrieve user info", error as Error);
    }
  }

  private async enrichUserDataOrgs(user: User): Promise<User> {
    try {
      const orgs = await this.orgRepo.getUserOrganizations(user.id);
      user.organizations = orgs;

      return user;
    } catch (error) {
      throw new DatabaseError("Failed to fetch user organizations", error as Error);
    }
  }

  // TODO: enrich user data with permissions

  private async generateAuthResult(user: User): Promise<AuthResult> {
    try {
      const payload: JWTPayload = {
        iss: this.config.jwtConfig.issuer ?? this.config.name,
        sub: user.id,
        exp: Math.floor(Date.now() / 1000) + this.getExpirationSeconds(),
        iat: Math.floor(Date.now() / 1000),
        user,
        ver: await this.getJWTVersion(user.id),
      };

      const accessToken = generateToken(payload, this.config.jwtConfig);

      // TODO: Implement refresh token

      return {
        accessToken,
        expiresIn: this.getExpirationSeconds(),
        user,
      };
    } catch (error) {
      throw new DatabaseError("Failed to generate authentication tokens", error as Error);
    }
  }

  private getExpirationSeconds(): number {
    const expStr = this.config.jwtConfig.expiresIn;
    if (expStr.endsWith("s")) {
      return Number.parseInt(expStr.slice(0, -1), 10);
    }
    if (expStr.endsWith("m")) {
      return Number.parseInt(expStr.slice(0, -1), 10) * 60;
    }
    if (expStr.endsWith("h")) {
      return Number.parseInt(expStr.slice(0, -1), 10) * 60 * 60;
    }
    if (expStr.endsWith("d")) {
      return Number.parseInt(expStr.slice(0, -1), 10) * 60 * 60 * 24;
    }
    throw new AuthKitError(
      `Invalid expiration format: ${expStr}. Expected format is <number>[s|m|h|d]`,
      "INVALID_EXPIRATION_FORMAT",
      400,
    );
  }

  private async getJWTVersion(userId: number): Promise<number> {
    try {
      const account = await this.accountRepo.getAccountById(userId);
      return account?.accJWTversion ?? 0;
    } catch (error) {
      throw new DatabaseError("Failed to get JWT version for user", error as Error);
    }
  }
}
