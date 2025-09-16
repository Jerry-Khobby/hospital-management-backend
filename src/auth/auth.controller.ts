import {Controller,Post,Body,HttpCode,HttpStatus} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ApiTags,ApiOperation,ApiResponse } from '@nestjs/swagger';


@ApiTags('auth')
@Controller('auth')
export class AuthController{
  constructor(private authService:AuthService){}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'User registration' })
  @ApiResponse({ status: 201, description: 'Registration successful.' })
  @Post('register')
  async register(@Body() registerDto:RegisterDto):Promise<{token:String}>{
    const {name,email,password,role} = registerDto;
    return this.authService.register(name,email,password,role);
  }

  //this would receive requests at '/auth/login'
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ status: 200, description: 'Login successful.' })
  @Post('login')
  async login(@Body() loginDto:LoginDto):Promise<{token:String}>{
    const {email,password,role} = loginDto;
    return this.authService.login(email,password,role);
  }
}