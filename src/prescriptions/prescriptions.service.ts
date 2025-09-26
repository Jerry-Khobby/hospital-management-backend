import {
  Injectable,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreatePrescriptionDto } from './dto/prescriptions.dto';

@Injectable()
export class PrescriptionsService {
  constructor(private readonly prisma: PrismaService) {}

  // Doctor only: create prescription for a patient
  async createPrescription(dto: CreatePrescriptionDto, requesterId: number, requesterRole: string) {
    if (requesterRole !== 'DOCTOR') {
      throw new ForbiddenException('Only doctors can create prescriptions');
    }

    // Check patient exists
    const patient = await this.prisma.patient.findUnique({ where: { id: dto.patientId } });
    if (!patient) throw new NotFoundException('Patient not found');

    // Create prescription
    return this.prisma.prescription.create({
      data: {
        medications: dto.medications,
        patientId: dto.patientId,
        doctorId: requesterId,
      },
      include: {
        patient: { select: { id: true, name: true } },
        doctor: { select: { id: true, name: true } },
      },
    });
  }

  // Get prescription by ID (Doctor, Patient (self), Pharmacist)
  async getPrescription(id: number, requesterId: number, requesterRole: string) {
    const prescription = await this.prisma.prescription.findUnique({
      where: { id },
      include: {
        patient: { select: { id: true, name: true } },
        doctor: { select: { id: true, name: true } },
      },
    });
    if (!prescription) throw new NotFoundException('Prescription not found');

    // Access control
    if (
      requesterRole === 'PATIENT' && prescription.patientId !== requesterId ||
      requesterRole === 'DOCTOR' && prescription.doctorId !== requesterId
    ) {
      throw new ForbiddenException('Not authorized to view this prescription');
    }
    // Pharmacist and Admin can view all
    return prescription;
  }

  // Get all prescriptions for a patient
  async getPrescriptionsForPatient(patientId: number, requesterId: number, requesterRole: string) {
    // Patient can view own, doctor can view if assigned, pharmacist can view all
    if (requesterRole === 'PATIENT' && requesterId !== patientId) {
      throw new ForbiddenException('Patients can only view their own prescriptions');
    }

    // If doctor, check if assigned (has at least one prescription for this patient)
    if (requesterRole === 'DOCTOR') {
      const anyPrescription = await this.prisma.prescription.findFirst({
        where: { patientId, doctorId: requesterId },
      });
      if (!anyPrescription) {
        throw new ForbiddenException('Doctor not assigned to this patient');
      }
    }

    // Pharmacist and Admin can view all
    return this.prisma.prescription.findMany({
      where: { patientId },
      orderBy: { createdAt: 'desc' },
      include: {
        patient: { select: { id: true, name: true } },
        doctor: { select: { id: true, name: true } },
      },
    });
  }
}