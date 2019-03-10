import { DynamicModule, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AuthController } from './auth.controller';
import { AuthService, JwtStrategy } from './auth.service';
import { AuthConfig, AuthModuleAsyncOptions, AuthModuleOptions, PasswordEncoder, UserDetailsService } from './auth.types';

const bashProviders = [
  {
    provide: AuthConfig,
    inject: [AuthModuleOptions],
    useFactory: (moduleOptions: AuthModuleOptions) => moduleOptions.config,
  },
  {
    provide: UserDetailsService,
    inject: [AuthModuleOptions],
    useFactory: (moduleOptions: AuthModuleOptions) => moduleOptions.userDetailService,
  },
  {
    provide: PasswordEncoder,
    inject: [AuthModuleOptions],
    useFactory: (moduleOptions: AuthModuleOptions) => moduleOptions.passwordEncoder,
  },
];

const authConfigModuleBase = {
  exports: [AuthConfig, PasswordEncoder, UserDetailsService],
};

@Module({})
export class AuthConfigModule {
  static forRoot(options: AuthModuleOptions): DynamicModule {
    return {
      module: AuthConfigModule,
      providers: [
        {
          provide: AuthModuleOptions,
          useValue: options,
        },
        ...bashProviders,
      ],
      ...authConfigModuleBase,
    };
  }

  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    return {
      module: AuthConfigModule,
      imports: options.imports,
      providers: [
        {
          inject: [...options.inject],
          provide: AuthModuleOptions,
          useFactory: options.useFactory,
        },
        ...bashProviders,
      ],
      ...authConfigModuleBase,
    };
  }
}

const authModuleBase = {
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
};

@Module({})
export class AuthModule {
  static forRoot(options: AuthModuleOptions): DynamicModule {
    return {
      module: AuthModule,
      imports: [
        AuthConfigModule.forRoot(options),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          secretOrPrivateKey: options.config.jwtSecret,
          signOptions: {
            expiresIn: options.config.accessTokenExpiresIn,
          },
        }),
      ],
      ...authModuleBase,
    };
  }

  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    return {
      module: AuthModule,
      imports: [
        ...options.imports,
        AuthConfigModule.forRootAsync(options),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          imports: [AuthConfigModule.forRootAsync(options)],
          inject: [AuthConfig],
          useFactory: (config: AuthConfig) => {
            return {
              secretOrPrivateKey: config.jwtSecret,
              signOptions: {
                expiresIn: config.accessTokenExpiresIn,
              },
            };
          },
        }),
      ],
      ...authModuleBase,
    };
  }
}
