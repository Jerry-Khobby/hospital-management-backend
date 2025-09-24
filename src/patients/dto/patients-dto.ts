import { IsString, IsInt, IsOptional, IsEmail, IsEnum, Min, Max, IsDateString } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreatePatientDto {
  @IsString()
  @Transform(({ value }) => value?.trim())
  name: string;

  @IsInt()
  @Min(0)
  @Max(150)
  age: number;

  @IsOptional()
  @IsString()
  @IsEnum(['male', 'female', 'M','F','f','m'])
  gender?: string;

  @IsOptional()
  @IsString()
  contactInfo?: string;
}

export class UpdatePatientDto {
  @IsOptional()
  @IsString()
  @Transform(({ value }) => value?.trim())
  name?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(150)
  age?: number;

  @IsOptional()
  @IsString()
  @IsEnum(['male', 'female', 'other'])
  gender?: string;

  @IsOptional()
  @IsString()
  contactInfo?: string;

  @IsOptional()
  @IsDateString()
  expectedUpdatedAt?: string;
}

export class PatientQueryDto {
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Transform(({ value }) => parseInt(value))
  limit?: number = 20;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Transform(({ value }) => parseInt(value))
  cursor?: number;

  @IsOptional()
  @IsString()
  @Transform(({ value }) => value?.trim())
  search?: string;
}

export class PatientResponseDto {
  id: number;
  name: string;
  age: number;
  gender: string;
  contactInfo?: string;
  createdById: number;
  createdBy?: {
    id: number;
    name: string;
    role: string;
  };
  createdAt: Date;
  updatedAt?: Date;
}