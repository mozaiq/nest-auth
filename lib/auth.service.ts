import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { PassportStrategy } from '@nestjs/passport';
import * as bcrypt from 'bcrypt';
import { ExtractJwt, Strategy } from 'passport-jwt';

import {
  AuthConfig,
  AuthenticatedUserDto,
  PasswordEncoder,
  REFREST_TOKEN_PERMISSION,
  SecuredMetadataKey,
  TokenDto,
  TokenType,
  UserDetails,
  UserDetailsService,
} from './auth.types';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly authConfig: AuthConfig,
    private readonly passwordEncoder: PasswordEncoder,
    private readonly userDetailsService: UserDetailsService,
  ) {}

  async loadValidEnabledUserDetails(username: string) {
    const userDetails = await this.userDetailsService.loadUserByUsername(username);

    if (!userDetails || !userDetails.enabled) {
      throw new UnauthorizedException();
    }

    return userDetails;
  }

  async authenticate(username: string, password: string) {
    const user = await this.loadValidEnabledUserDetails(username);

    const result = await this.passwordEncoder.verify(password, user.password);
    if (!result) {
      throw new UnauthorizedException();
    }

    if (user.password !== password) {
      throw new UnauthorizedException();
    }

    return this.createToken(username);
  }

  async createToken(username: string) {
    const jwtPayload: TokenDto = {
      username,
      type: TokenType.ACCESS,
    };

    const accessToken = await this.jwtService.signAsync(jwtPayload);
    const refreshToken = await this.jwtService.signAsync(
      {
        ...jwtPayload,
        type: TokenType.REFRESH,
      },
      {
        expiresIn: this.authConfig.refreshTokenExpiresIn,
      },
    );

    return {
      accessToken,
      refreshToken,
    };
  }
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService, readonly authConfig: AuthConfig) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: authConfig.jwtSecret,
    });
  }

  async validate(payload: TokenDto) {
    const userDetails = await this.authService.loadValidEnabledUserDetails(payload.username);
    const userDto: AuthenticatedUserDto = {
      id: userDetails.id,
      username: payload.username,
      permissions: TokenType.REFRESH === payload.type ? [REFREST_TOKEN_PERMISSION] : userDetails.permissions,
    };
    return userDto;
  }
}

@Injectable()
export class SecuredGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const permission = this.reflector.get<string>(SecuredMetadataKey, context.getHandler());
    if (!permission) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const user: AuthenticatedUserDto = request.user;
    return user && user.permissions.includes(permission);
  }
}

export class PlainPasswordEncoder implements PasswordEncoder {
  encrypt(plain: string) {
    return plain;
  }
  verify(plain: string, encrypted: string) {
    return plain === encrypted;
  }
}

export class BCryptPasswordEncoder implements PasswordEncoder {
  async encrypt(plain: string) {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(plain, salt);
  }
  verify(plain: string, encrypted: string) {
    return bcrypt.compare(plain, encrypted);
  }
}

export class InMemoryUserDetailsService implements UserDetailsService {
  private users: UserDetails[] = [];

  loadUserByUsername(username: string) {
    return this.users.find((user) => user.username === username);
  }

  with(username: string, password: string, permissions: string[] = []) {
    this.users.push({
      id: this.users.length + 1,
      enabled: true,
      username,
      password,
      permissions,
    });

    return this;
  }
}
