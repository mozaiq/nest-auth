import { createParamDecorator, ReflectMetadata } from '@nestjs/common';
import { ModuleMetadata } from '@nestjs/common/interfaces';
import { ApiModelProperty } from '@nestjs/swagger';
import { IsDefined, IsString } from 'class-validator';

// Constants
export const REFREST_TOKEN_PERMISSION = 'REFREST_TOKEN';

// Decorators
export const SecuredMetadataKey = 'permission';
export const Secured = (permission: string) => ReflectMetadata(SecuredMetadataKey, permission);

export const UserId = createParamDecorator((data, { user }) => user.id);
export const Username = createParamDecorator((data, { user }) => user.username);

// Enums
export enum TokenType {
  ACCESS = 'ACCESS',
  REFRESH = 'REFRESH',
}

// Interfaces
export interface UserDetails {
  id: number;
  username: string;
  password: string;
  enabled: boolean;
  permissions: string[];
}

export abstract class UserDetailsService {
  abstract loadUserByUsername(username: string): UserDetails | Promise<UserDetails>;
}

export abstract class PasswordEncoder {
  abstract encrypt(plain: string): string | Promise<string>;
  abstract verify(plain: string, encrypted: string): boolean | Promise<boolean>;
}

export abstract class AuthModuleOptions {
  readonly config: AuthConfig;
  readonly userDetailService: UserDetailsService;
  readonly passwordEncoder: PasswordEncoder;
}

export interface AuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  readonly inject?: any[];
  readonly useFactory?: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
}

// Classes
export class TokenDto {
  readonly username: string;
  readonly type: TokenType;
}

export class AuthenticatedUserDto {
  readonly id: number;
  readonly username: string;
  readonly permissions: string[];
}

export class AuthConfig {
  @IsDefined()
  @IsString()
  readonly jwtSecret: string;

  @IsDefined()
  @IsString()
  readonly accessTokenExpiresIn: string;

  @IsDefined()
  @IsString()
  readonly refreshTokenExpiresIn: string;
}

export class AuthenticateRequest {
  @IsDefined()
  @ApiModelProperty()
  readonly username: string;

  @IsDefined()
  @IsString()
  @ApiModelProperty()
  readonly password: string;
}

export class AuthenticateResponse {
  @ApiModelProperty()
  readonly accessToken: string;

  @ApiModelProperty()
  readonly refreshToken: string;
}
