import {
  Controller,
  Post,
  Body,
  Req,
  Get,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request } from 'express';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(
    @Body('email') email: string,
    @Body('password') password: string,
    @Body('name') name: string,
    @Req() req: Request,
  ) {
    return this.authService.register(email, password, name, req);
  }

  @Post('login')
  login(
    @Body('email') email: string,
    @Body('password') password: string,
    @Req() req: Request,
  ) {
    return this.authService.login(email, password, req);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('me')
  getMe(@Req() req: Request) {
    return req.user;
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  logout(@Req() req: Request) {
    const user = req.user as any; // payload: { sub: string, email: string }
    return this.authService.logout(user.sub);
  }

  @Post('refresh')
  refresh(@Body('refreshToken') refreshToken: string) {
    return this.authService.refreshTokens(refreshToken);
  }
}