import { 
  Injectable, 
  ConflictException, 
  BadRequestException,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException 
} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as bcrypt from 'bcrypt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import { UserResponseDto } from "./dto/user-response.dto";
import { UserQueryDto } from "./dto/user-query.dto";
import { Prisma, Role } from "generated/prisma";
import { UpdateUserDto } from "./dto/update-user.dto";

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);
  private readonly CACHE_TTL_MS = 5 * 60 * 1000;
  private readonly USERS_CACHE_KEY = 'all_users';
  private readonly USER_CACHE_PREFIX = 'user:';
  private readonly ROLE_CACHE_PREFIX = 'users:role:';

  constructor(
    private readonly prisma: PrismaService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache
  ) {}

  // ========== FIND ALL USERS WITH PAGINATION ==========
  async findAllUsers(query: UserQueryDto = {}) {
    const {
      page = 1,
      limit = 10,
      role,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = query;

    const cacheKey = this.getUsersCacheKey(query);

    try {
      const cachedData = await this.cacheManager.get(cacheKey);
      if (cachedData) {
        this.logger.log('Returning users from cache');
        return cachedData;
      }

      this.logger.log('Cache miss - fetching users from database');
      
      const where: Prisma.UserWhereInput = {};
      if (role) where.role = role;

      const skip = (page - 1) * limit;
      const total = await this.prisma.user.count({ where });

      const users = await this.prisma.user.findMany({
        where,
        skip,
        take: limit,
        orderBy: { [sortBy]: sortOrder },
      });

      const userDtos = users.map(user => new UserResponseDto(user));

      const result = {
        users: userDtos,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      };

      await this.cacheManager.set(cacheKey, result, this.CACHE_TTL_MS);
      
      return result;
    } catch (error) {
      this.logger.error('Error in findAllUsers', error);
      throw new InternalServerErrorException('Failed to fetch users');
    }
  }

  // ========== FIND USER BY ID ==========
  async findUserById(id: number): Promise<UserResponseDto> {
    this.validateUserId(id);

    const cacheKey = this.getUserCacheKey(id);

    try {
      const cachedUser = await this.cacheManager.get<UserResponseDto>(cacheKey);
      if (cachedUser) {
        this.logger.log(`Returning user ${id} from cache`);
        return cachedUser;
      }

      const user = await this.prisma.user.findUnique({
        where: { id },
      });

      if (!user) throw new NotFoundException('User not found');

      const userDto = new UserResponseDto(user);
      await this.cacheManager.set(cacheKey, userDto, this.CACHE_TTL_MS);
      
      return userDto;
    } catch (error) {
      this.logger.error(`Error finding user by id ${id}`, error);
      throw error;
    }
  }

  // ========== UPDATE USER ==========
  async updateUser(id: number, updateData: UpdateUserDto): Promise<UserResponseDto> {
    this.validateUserId(id);

    try {
      const existingUser = await this.prisma.user.findUnique({
        where: { id },
      });
      if (!existingUser) throw new NotFoundException('User not found');

      if (updateData.email && updateData.email !== existingUser.email) {
        const emailExists = await this.prisma.user.findUnique({
          where: { email: updateData.email },
        });
        if (emailExists) throw new ConflictException('Email already exists');
      }

      let hashedPassword: string | undefined;
      if (updateData.password) {
        hashedPassword = await bcrypt.hash(updateData.password, 12);
      }

      const updatePayload: Prisma.UserUpdateInput = {
        ...(updateData.email && { email: updateData.email }),
        ...(updateData.name && { name: updateData.name }),
        ...(updateData.role && { role: updateData.role }),
        ...(hashedPassword && { password: hashedPassword }),
      };

      const updatedUser = await this.prisma.user.update({
        where: { id },
        data: updatePayload,
      });

      const userDto = new UserResponseDto(updatedUser);

      await this.clearUserCache(id);
      await this.clearAllUsersCache();
      await this.clearRoleBasedCaches(updatedUser.role);

      return userDto;
    } catch (error) {
      this.logger.error(`Error updating user ${id}`, error);
      throw error;
    }
  }

  // ========== DELETE USER (HARD DELETE) ==========
  async deleteUser(id: number): Promise<void> {
    this.validateUserId(id);

    try {
      await this.prisma.user.delete({
        where: { id },
      });

      await this.clearUserCache(id);
      await this.clearAllUsersCache();

      this.logger.log(`User ${id} deleted successfully`);
    } catch (error) {
      this.logger.error(`Error deleting user ${id}`, error);
      throw new InternalServerErrorException('Failed to delete user');
    }
  }

  // ========== ROLE-BASED QUERIES ==========
  async findUsersByRole(role: Role, query: UserQueryDto = {}) {
    if (!Object.values(Role).includes(role)) {
      throw new BadRequestException('Invalid role');
    }

    const cacheKey = this.getRoleCacheKey(role, query);

    try {
      const cachedData = await this.cacheManager.get(cacheKey);
      if (cachedData) {
        this.logger.log(`Returning ${role} users from cache`);
        return cachedData;
      }

      const result = await this.findAllUsers({
        ...query,
        role,
      });

      await this.cacheManager.set(cacheKey, result, this.CACHE_TTL_MS);
      
      return result;
    } catch (error) {
      this.logger.error(`Error finding users by role ${role}`, error);
      throw new InternalServerErrorException('Failed to fetch users by role');
    }
  }

  // ========== CACHE HELPERS ==========
  private async clearUserCache(id: number): Promise<void> {
    await this.cacheManager.del(this.getUserCacheKey(id));
  }

  private async clearAllUsersCache(): Promise<void> {
    await this.cacheManager.del(this.USERS_CACHE_KEY);
  }

  private async clearRoleBasedCaches(role: Role): Promise<void> {
    await this.cacheManager.del(this.getRoleCacheKey(role));
  }

  private getUserCacheKey(id: number): string {
    return `${this.USER_CACHE_PREFIX}${id}`;
  }

  private getUsersCacheKey(query: UserQueryDto): string {
    const params = Object.entries(query)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}:${value}`)
      .join('|');
    return `users:${params}`;
  }

  private getRoleCacheKey(role: Role, query?: UserQueryDto): string {
    if (query) {
      const params = this.getUsersCacheKey(query);
      return `${this.ROLE_CACHE_PREFIX}${role}:${params}`;
    }
    return `${this.ROLE_CACHE_PREFIX}${role}`;
  }

  private validateUserId(id: number): void {
    if (!id || id <= 0 || !Number.isInteger(id)) {
      throw new BadRequestException('Invalid user ID');
    }
  }
}
