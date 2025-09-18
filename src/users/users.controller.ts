import { 
  Controller, 
  Body, 
  Get, 
  Post, 
  Put, 
  Delete, 
  Param, 
  Query, 
  HttpCode, 
  HttpStatus, 
  ParseIntPipe 
} from "@nestjs/common";
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse, 
  ApiParam, 
  ApiQuery 
} from "@nestjs/swagger";
import { UserService } from "./users.service";
import { UserQueryDto } from "./dto/user-query.dto";
import { UpdateUserDto } from "./dto/update-user.dto";
import { UserResponseDto } from "./dto/user-response.dto";
import { Role } from "generated/prisma";

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private userService: UserService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get all users with pagination and filtering' })
  @ApiResponse({ 
    status: 200, 
    description: 'List of users retrieved successfully.',
    type: [UserResponseDto]
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default: 1)' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (default: 10)' })
  @ApiQuery({ name: 'role', required: false, enum: Role, description: 'Filter by user role' })
  @ApiQuery({ name: 'sortBy', required: false, type: String, description: 'Sort field (default: createdAt)' })
  @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'], description: 'Sort order (default: desc)' })
  async getAllUsers(@Query() query: UserQueryDto) {
    return this.userService.findAllUsers(query);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get user by ID' })
  @ApiParam({ name: 'id', type: Number, description: 'User ID' })
  @ApiResponse({ 
    status: 200, 
    description: 'User retrieved successfully.',
    type: UserResponseDto
  })
  @ApiResponse({ status: 404, description: 'User not found.' })
  @ApiResponse({ status: 400, description: 'Invalid user ID.' })
  async getUserById(@Param('id', ParseIntPipe) id: number): Promise<UserResponseDto> {
    return this.userService.findUserById(id);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update user by ID' })
  @ApiParam({ name: 'id', type: Number, description: 'User ID' })
  @ApiResponse({ 
    status: 200, 
    description: 'User updated successfully.',
    type: UserResponseDto
  })
  @ApiResponse({ status: 404, description: 'User not found.' })
  @ApiResponse({ status: 400, description: 'Invalid user ID or update data.' })
  @ApiResponse({ status: 409, description: 'Email already exists.' })
  async updateUser(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUserDto: UpdateUserDto
  ): Promise<UserResponseDto> {
    return this.userService.updateUser(id, updateUserDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete user by ID' })
  @ApiParam({ name: 'id', type: Number, description: 'User ID' })
  @ApiResponse({ status: 204, description: 'User deleted successfully.' })
  @ApiResponse({ status: 404, description: 'User not found.' })
  @ApiResponse({ status: 400, description: 'Invalid user ID.' })
  async deleteUser(@Param('id', ParseIntPipe) id: number): Promise<void> {
    return this.userService.deleteUser(id);
  }

  @Get('role/:role')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get users by role with pagination and filtering' })
  @ApiParam({ name: 'role', enum: Role, description: 'User role' })
  @ApiResponse({ 
    status: 200, 
    description: 'Users by role retrieved successfully.',
    type: [UserResponseDto]
  })
  @ApiResponse({ status: 400, description: 'Invalid role.' })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Page number (default: 1)' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (default: 10)' })
  @ApiQuery({ name: 'sortBy', required: false, type: String, description: 'Sort field (default: createdAt)' })
  @ApiQuery({ name: 'sortOrder', required: false, enum: ['asc', 'desc'], description: 'Sort order (default: desc)' })
  async getUsersByRole(
    @Param('role') role: Role,
    @Query() query: UserQueryDto
  ) {
    return this.userService.findUsersByRole(role, query);
  }
}