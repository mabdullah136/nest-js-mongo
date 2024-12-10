import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  Query,
  HttpCode,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { json } from 'stream/consumers';
import {
  BadRequestException,
  NotFoundException,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @UseInterceptors(FileInterceptor('file'))
  @HttpCode(201)
  async register(
    @Body() body: { username: string; email: string; password: string },
  ) {
    const user = await this.authService.register(
      body.username,
      body.email,
      body.password,
    );
    return {
      status: 'success',
      message: 'User created Successfully',
      data: user,
    };
  }

  @Post('login')
  @UseInterceptors(FileInterceptor('file'))
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    const user = await this.authService.validateUser(body.email, body.password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const token = await this.authService.login(user);
    return {
      status: 'success',
      message: 'User logged in Successfully',
      data: token,
    };
  }

  @Get('list')
  @HttpCode(200)
  async profile(@Body() body: { token: string }) {
    const user = await this.authService.findUser();
    return {
      status: 'success',
      message: 'User list',
      data: user,
    };
  }

  @Get('profile')
  @UseInterceptors(FileInterceptor('file'))
  @HttpCode(200)
  async profile1(@Query('id') id: string) {
    try {
      const user = await this.authService.findUserById(id);
      if (!user) {
        throw new NotFoundException('User not found');
      }
      return {
        status: 'success',
        message: 'User profile',
        data: user,
      };
    } catch (error) {
      throw new BadRequestException('Invalid user ID');
    }
  }

  @Post('update')
  @UseInterceptors(FileInterceptor('file'))
  @HttpCode(200)
  async update(
    @Query('id') id: string,
    @Body()
    body: {
      username: string;
      oldPassword: string;
      password: string;
    },
  ) {
    const user = await this.authService.updateUser(
      id,
      body.username,
      body.oldPassword,
      body.password,
    );
    return {
      status: 'success',
      message: 'User updated Successfully',
      data: user,
    };
  }
}
