import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Auth, AuthSchema } from './schemas/auth.schema';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
console.log(AuthController); // Place this after importing AuthController

import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Auth.name, schema: AuthSchema }]),
    JwtModule.register({
      secret:
        'bfd3cd08c979d5bfb5381d36e44e0f728d74af0ceb500e35368876f2120abf24895d02bc09e8b587634660645c9019400a325b5dcde097f15b8441719f4656f8', // Use environment variables in production
      signOptions: { expiresIn: '1h' },
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
