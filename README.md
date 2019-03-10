## Description

Nest auth module based on nest-jwt and nest-passport.

Easily setup statless authentication with guards and login/refreshToken endpoints.

## Installation

```bash
$ npm i --save @mozaiq/nest-auth
```

## Usage

Example usage with hard wired users for testing

```typescript
import { AuthModule, InMemoryUserDetailsService, PlainPasswordEncoder } from '@mozaiq/nest-auth';

@Module({
  imports: [
    AuthModule.forRoot({
      config: {
        jwtSecret: 'jwtSecret',
        accessTokenExpiresIn: '1h',
        refreshTokenExpiresIn: '1m',
      },
      userDetailService: new InMemoryUserDetailsService()
        .with('foobar@examle.com', 'secret', ['PERMISSION1'])
        .with(...),
      passwordEncoder: new PlainPasswordEncoder(),
    }),
  ],
  providers: [...],
})
export class AuthModule {}
```

Protect your endpoints

```typescript
import { Secured, SecuredGuard, UserId } from '@mozaiq/nest-auth';
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth } from '@nestjs/swagger';

import { AppService } from './app.service';

@ApiBearerAuth()
@UseGuards(AuthGuard(), SecuredGuard)
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Secured('REQUIRED_PERMISSION')
  getHello(@UserId() userId: number): string {
    console.log('The logged in user id is:', userId);
    return this.appService.getHello();
  }
}
```

Use async if you want to provide custom configuration

```typescript
import { AuthModule, InMemoryUserDetailsService, PlainPasswordEncoder } from '@mozaiq/nest-auth';

@Module({
  imports: [
    AuthModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ApplicationConfig],
      useFactory: (config: ApplicationConfig) => ({
        config: config.auth,
        userDetailService: new InMemoryUserDetailsService()
          .with('foobar@examle.com', 'secret', ['PERMISSION1'])
          .with(...),
        passwordEncoder: new PlainPasswordEncoder(),
      }),
    }),
  ],
  providers: [...],
})
export class AppModule {}
```

Create your custom implementations

```typescript
import { PasswordEncoder, UserDetailsService } from '@mozaiq/nest-auth';

export class MyPasswordEncoder implements PasswordEncoder {
  ...
}

export class MyUserDetailsService implements UserDetailsService {
  ...
}

```

## License

[MIT licensed](LICENSE)
