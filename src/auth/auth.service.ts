import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from 'nestjs-typegoose';
import { UserModel } from '../user/user.model';
import { ModelType } from '@typegoose/typegoose/lib/types';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './auth.dto';
import { compare } from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(UserModel) private readonly userModel: ModelType<UserModel>,
    private readonly jwtService: JwtService,
  ) {
  }

  async login(dto: AuthDto) {
    const user = await this.validateUser(dto);
    const tokens = await this.issueTokenPair(user._id.toString());

    return {
      user: this.returnUserFields(user),
      ...tokens
    }
  }

  async validateUser(dto: AuthDto) {
    const user = await this.userModel.findOne({ email: dto.email });
    if (!user) throw new UnauthorizedException('User not found');

    const isValidPassword = await compare(dto.password, user.password);
    if (!isValidPassword) throw new UnauthorizedException('Invalid password');

    return user;
  }

  async issueTokenPair(id: string) {
    const payload = { _id: id };

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '30m',
    });

    return { accessToken };
  }

  async returnUserFields(user: UserModel) {
    return {
      _id: user._id,
      email: user.email,
    };
  }
}
