import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user/user.entity';
import { Request } from 'express';
import * as crypto from 'crypto';
import { MailService } from '../mail/mail.service';

@Injectable()
export class AuthService {

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
  ) {}

  async register(
    email: string,
    password: string,
    name: string,
    req: Request,
  ) {
    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new BadRequestException('Bu e-posta zaten kullanılıyor.');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const emailVerificationToken = crypto.randomBytes(32).toString('hex');

    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      name,
      lastLoginIp: req.ip,
      userAgent: req.headers['user-agent'] || '',
      emailVerificationToken,
    });

    await this.userRepository.save(user);

    const tokens = await this.generateTokens(user);
    user.refreshToken = await bcrypt.hash(tokens.refreshToken, 10);
    await this.userRepository.save(user);

    // E-posta gönderme kısmı burada yapılacak (postayı göndermek için)
    // Bu aşamada postayı göndermek için bir servis yazacağız.
    await this.mailService.sendVerificationEmail(email, emailVerificationToken);

    return { message: 'Kayıt başarılı. E-posta adresinizi doğrulamak için gelen kutunuzu kontrol edin.' };
  }

  async login(email: string, password: string, req: Request) {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Geçersiz e-posta ya da şifre.');
    }

    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      throw new UnauthorizedException('Geçersiz e-posta ya da şifre.');
    }

    user.lastLoginIp = req.ip || '0.0.0.0';
    user.userAgent = req.headers['user-agent'] || '';
    await this.userRepository.save(user);

    const tokens = await this.generateTokens(user);
    user.refreshToken = await bcrypt.hash(tokens.refreshToken, 10);
    await this.userRepository.save(user);

    return tokens;
  }

  private async generateTokens(user: User) {
    const payload = { sub: user.id, email: user.email };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: '15m',
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    return { accessToken, refreshToken };
  }

  async refreshTokens(refreshToken: string) {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token gerekli');
    }
  
    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch {
      throw new UnauthorizedException('Geçersiz refresh token');
    }
  
    const user = await this.userRepository.findOne({
      where: { id: payload.sub },
    });
  
    if (!user || !user.refreshToken) {
      throw new UnauthorizedException('Refresh token bulunamadı veya eşleşmiyor');
    }
  
    const isMatch = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!isMatch) {
      throw new UnauthorizedException('Refresh token uyuşmuyor');
    }
  
    const tokens = await this.generateTokens(user);
    user.refreshToken = await bcrypt.hash(tokens.refreshToken, 10);
    await this.userRepository.save(user);
  
    return tokens;
  }

  async logout(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('Kullanıcı bulunamadı.');
    }
  
    user.refreshToken = null;
    await this.userRepository.save(user);
  
    return { message: 'Çıkış başarılı.' };
  }

  async verifyEmail(token: string) {
    const user = await this.userRepository.findOne({ where: { emailVerificationToken: token } });
    if (!user) throw new BadRequestException('Geçersiz veya süresi dolmuş token.');
  
    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    await this.userRepository.save(user);
    return { message: 'E-posta doğrulandı.' };
  }
}