// src/auth/dto/register.dto.ts
import { IsEmail, IsString, IsEnum, MinLength, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;

  @IsNotEmpty()
  @IsEnum(['ADMIN', 'DOCTOR', 'NURSE', 'PATIENT'])
  role: 'ADMIN' | 'DOCTOR' | 'NURSE' | 'PATIENT';
}