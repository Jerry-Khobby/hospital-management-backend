import { 
  Injectable, 
  UnauthorizedException, 
  ConflictException, 
  BadRequestException,
  Inject,
  Logger 
} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager'; // Use import type

// Define interface for cached user
interface CachedUser {
  id: number;
  password: string;
  role: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly jwtSecret = process.env.JWT_SECRET_KEY || 'fallback-secret'; // Add fallback
  private readonly maxLoginAttempts = 5;
  private readonly lockTime = 15 * 60 * 1000; // 15 minutes

  constructor(
    private prisma: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {}

  // Redis-based rate limiting
  private async checkLoginAttempts(email: string): Promise<void>{
    const lockoutKey = `lockout:${email}`;
    const attemptsKey = `attempts:${email}`;
    
    // Check if user is locked out
    const isLockedOut = await this.cacheManager.get<boolean>(lockoutKey);
    if (isLockedOut) {
      throw new UnauthorizedException('Account temporarily locked. Try again in 15 minutes.');
    }

    // Get current attempt count
    const attempts: number = (await this.cacheManager.get<number>(attemptsKey)) || 0;
    if (attempts >= this.maxLoginAttempts) {
      // Lock the account
      await this.cacheManager.set(lockoutKey, true, this.lockTime);
      await this.cacheManager.del(attemptsKey);
      throw new UnauthorizedException('Too many failed attempts. Account locked for 15 minutes.');
    }
  }

  private async incrementLoginAttempts(email: string): Promise<void> {
    const attemptsKey = `attempts:${email}`;
    const attempts: number = (await this.cacheManager.get<number>(attemptsKey)) || 0;
    await this.cacheManager.set(attemptsKey, attempts + 1, 3600); // 1 hour TTL
  }

  private async resetLoginAttempts(email: string): Promise<void> {
    const attemptsKey = `attempts:${email}`;
    const lockoutKey = `lockout:${email}`;
    await this.cacheManager.del(attemptsKey);
    await this.cacheManager.del(lockoutKey);
  }

  // Password validation and hashing
  async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  async validatePassword(password: string): Promise<void> {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException('Password must be at least 8 characters long');
    }
    if (!hasUpperCase || !hasLowerCase) {
      throw new BadRequestException('Password must contain both uppercase and lowercase letters');
    }
    if (!hasNumber) {
      throw new BadRequestException('Password must contain numbers');
    }
    if (!hasSpecialChar) {
      throw new BadRequestException('Password must contain special characters');
    }
  }

  // JWT Token generation
  async generateToken(userId: number): Promise<string> {
    return jwt.sign(
      { 
        userId, 
        iat: Math.floor(Date.now() / 1000)
      }, 
      this.jwtSecret, 
      { 
        expiresIn: '1h',
        algorithm: 'HS256' 
      }
    );
  }

  // User registration with Redis caching for duplicate check
  async register(
    name: string,
    email: string,
    password: string,
    role: 'ADMIN' | 'DOCTOR' | 'NURSE' | 'PATIENT' | 'PHARMACIST'
  ): Promise<{ token: string }> {
    try {
      await this.validatePassword(password);
      const hashedPassword = await this.hashPassword(password);

      // Cache user existence check
      const userCacheKey = `user:${email}`;
      const cachedUser = await this.cacheManager.get<boolean>(userCacheKey);
      
      if (cachedUser) {
        throw new ConflictException('User with this email already exists');
      }

      // Database check
      const existingUser = await this.prisma.user.findUnique({
        where: { email },
        select: { id: true }
      });

      if (existingUser) {
        await this.cacheManager.set(userCacheKey, true, 300);
        throw new ConflictException('User with this email already exists');
      }

      const user = await this.prisma.user.create({
        data: { email, password: hashedPassword, name, role },
        select: { id: true }
      });

      await this.cacheManager.set(userCacheKey, true, 300);

      const token = await this.generateToken(user.id);
      
      this.logger.log(`User registered successfully: ${email}`);
      return { token };

    } catch (error) {
      this.logger.error(`Registration failed for ${email}: ${error.message}`);
      throw error;
    }
  }

  // Login with Redis-based rate limiting
  async login(
    email: string,
    password: string,
    role: 'ADMIN' | 'DOCTOR' | 'NURSE' | 'PATIENT' | 'PHARMACIST'
  ): Promise<{ token: string }> {
    try {
      await this.checkLoginAttempts(email);

      // Cache user lookup
      const userCacheKey = `user:${email}`;
      let user = await this.cacheManager.get<CachedUser>(userCacheKey);

      if (!user) {
        const dbUser = await this.prisma.user.findUnique({
          where: { email },
          select: { id: true, password: true, role: true }
        });
        
        if (dbUser) {
          user = {
            id: dbUser.id,
            password: dbUser.password,
            role: dbUser.role
          };
          await this.cacheManager.set(userCacheKey, user, 300);
        }
      }

      if (!user || user.role !== role) {
        await this.incrementLoginAttempts(email);
        throw new UnauthorizedException('Invalid credentials');
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        await this.incrementLoginAttempts(email);
        throw new UnauthorizedException('Invalid credentials');
      }

      await this.resetLoginAttempts(email);

      const token = await this.generateToken(user.id);
      
      this.logger.log(`User logged in successfully: ${email}`);
      return { token };

    } catch (error) {
      this.logger.error(`Login failed for ${email}: ${error.message}`);
      throw error;
    }
  }

  // Token validation with Redis blacklisting support
  async validateToken(token: string): Promise<{ userId: number }> {
    try {
      const blacklistKey = `blacklist:${token}`;
      const isBlacklisted = await this.cacheManager.get<boolean>(blacklistKey);
      if (isBlacklisted) {
        throw new UnauthorizedException('Token is invalid');
      }

      const decoded = jwt.verify(token, this.jwtSecret) as { userId: number };
      return { userId: decoded.userId };
    } catch (error) {
      throw new UnauthorizedException('Invalid token or expired token');
    }
  }

  // Logout functionality to blacklist token
  async logout(token: string): Promise<void> {
    try {
      const decoded = jwt.verify(token, this.jwtSecret) as { exp: number };
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      
      if (ttl > 0) {
        const blacklistKey = `blacklist:${token}`;
        await this.cacheManager.set(blacklistKey, true, ttl);
      }
    } catch (error) {
      this.logger.warn(`Logout attempted with invalid token: ${error.message}`);
    }
  }
}