import { IsInt, IsString, IsNotEmpty } from 'class-validator';

export class CreatePrescriptionDto {
  @IsInt()
  patientId: number;

  @IsString()
  @IsNotEmpty()
  medications: string;
}

export class PrescriptionResponseDto {
  id: number;
  medications: string;
  patientId: number;
  doctorId: number;
  createdAt: Date;
  patient?: {
    id: number;
    name: string;
  };
  doctor?: {
    id: number;
    name: string;
  };
}