export class PatientDto {
  id?: number;
  name: string;
  age: number;
  gender: string;
  contactInfo?: string;
  createdById: number;
  createdAt?: Date;
}