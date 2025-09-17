// src/auth/dto/register.dto.ts
import { IsEmail, IsString, IsEnum, MinLength, IsNotEmpty } from 'class-validator';

export class RegisterDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  password: string;

  @IsNotEmpty()
  @IsEnum(['ADMIN', 'DOCTOR', 'NURSE', 'PATIENT','PHARMACIST'])
  role: 'ADMIN' | 'DOCTOR' | 'NURSE' | 'PATIENT'|'PHARMACIST';
}