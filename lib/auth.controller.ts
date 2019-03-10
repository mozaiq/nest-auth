import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth, ApiCreatedResponse, ApiOperation } from '@nestjs/swagger';

import { AuthService, SecuredGuard } from './auth.service';
import { AuthenticateRequest, AuthenticateResponse, REFREST_TOKEN_PERMISSION, Secured, Username } from './auth.types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOperation({ operationId: 'login', title: 'Login' })
  @ApiCreatedResponse({ type: AuthenticateResponse })
  login(@Body() { username, password }: AuthenticateRequest) {
    return this.authService.authenticate(username, password);
  }

  @Post('refresh-token')
  @ApiBearerAuth()
  @ApiOperation({ operationId: 'refreshToken', title: 'Refresh token' })
  @ApiCreatedResponse({ type: AuthenticateResponse })
  @Secured(REFREST_TOKEN_PERMISSION)
  @UseGuards(AuthGuard(), SecuredGuard)
  refreshToken(@Username() username: string) {
    return this.authService.createToken(username);
  }
}
