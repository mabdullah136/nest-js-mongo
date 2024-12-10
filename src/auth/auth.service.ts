import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Auth } from './schemas/auth.schema';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Types } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Auth.name) private authModel: Model<Auth>,
    private jwtService: JwtService,
  ) {}

  async register(
    username: string,
    email: string,
    password: string,
  ): Promise<Auth> {
    try {
      if (!password || password.trim().length === 0) {
        throw new Error('Password cannot be empty');
      }

      if (!username || username.trim().length === 0) {
        throw new Error('Username cannot be empty');
      }

      if (!email || email.trim().length === 0) {
        throw new Error('Email cannot be empty');
      }

      if (!email.includes('@')) {
        throw new Error('Invalid email');
      }

      const existingUser = await this.authModel.findOne({ email });
      if (existingUser) {
        throw new Error('Email is already taken');
      }

      if (password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }

      const salt = await bcrypt.genSalt();
      if (!salt) {
        throw new Error('Failed to generate salt');
      }

      const hashedPassword = await bcrypt.hash(password, salt);
      if (!hashedPassword) {
        throw new Error('Failed to hash password');
      }

      const newUser = new this.authModel({
        username,
        email,
        password: hashedPassword,
        salt,
      });

      return newUser.save();
    } catch (error) {
      console.error('Error in register method:', error);
      throw error;
    }
  }

  async validateUser(email: string, password: string): Promise<Auth | null> {
    const user = await this.authModel.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      return user;
    }
    return null;
  }

  async login(user: Auth): Promise<{ access_token: string }> {
    const payload = { email: user.email, sub: user._id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async findUser(): Promise<Auth[]> {
    return this.authModel.find().select('-password -salt').exec();
  }

  async findUserById(id: string): Promise<Auth | null> {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error('Invalid ID format');
    }
    return this.authModel.findById(id).select('-password -salt').exec();
  }

  async updateUser(
    id: string,
    username: string,
    oldPassword: string,
    password: string,
  ): Promise<Auth> {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error('Invalid ID format');
    }

    const user = await this.authModel.findById(id);
    if (!user) {
      throw new Error('User not found');
    }

    if (username) {
      user.username = username;
    }

    if (password) {
      if (password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
      }
      if (!oldPassword) {
        throw new Error('Old password is required');
      }
      const validPassword = await this.validateOldPassword(id, oldPassword);
      if (!validPassword) {
        throw new Error('Invalid old password');
      }

      const salt = await bcrypt.genSalt();
      if (!salt) {
        throw new Error('Failed to generate salt');
      }

      const hashedPassword = await bcrypt.hash(password, salt);
      if (!hashedPassword) {
        throw new Error('Failed to hash password');
      }
      user.password = hashedPassword;
      user.salt = salt;
    }
    user.save();
    const updatedUser = await this.authModel
      .findById(id)
      .select('-password -salt')
      .exec();
    return updatedUser;
  }

  async validateOldPassword(id: string, oldPassword: string): Promise<boolean> {
    const user = await this.authModel.findById(id);
    if (user && (await bcrypt.compare(oldPassword, user.password))) {
      return true;
    }
    return false;
  }
}
