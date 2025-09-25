import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateAppointmentDto, UpdateAppointmentDto, AppointmentStatus } from './dto/appointments.dto';

@Injectable()
export class AppointmentsService {
  constructor(private readonly prisma: PrismaService) {}

  // Book an appointment (Patients only)
  async createAppointment(dto: CreateAppointmentDto, requesterId: number, requesterRole: string) {
    // Only patients can book their own appointments
    if (requesterRole !== 'PATIENT' || requesterId !== dto.patientId) {
      throw new ForbiddenException('Only patients can book their own appointments');
    }

    // Check doctor exists and is a DOCTOR
    const doctor = await this.prisma.user.findUnique({ where: { id: dto.doctorId } });
    if (!doctor || doctor.role !== 'DOCTOR') {
      throw new BadRequestException('Doctor not found');
    }

    // Check for overlapping appointments (scalability: indexed queries)
    const overlap = await this.prisma.appointment.findFirst({
      where: {
        doctorId: dto.doctorId,
        date: dto.date,
        status: { in: ['CONFIRMED', 'PENDING'] },
      },
    });
    if (overlap) {
      throw new BadRequestException('Doctor already has an appointment at this time');
    }

    // Create appointment
    return this.prisma.appointment.create({
      data: {
        patientId: dto.patientId,
        doctorId: dto.doctorId,
        date: new Date(dto.date),
        status: AppointmentStatus.PENDING,
      },
    });
  }

  // Get appointment details (Patient, Doctor, or Admin)
  async getAppointment(id: number, requesterId: number, requesterRole: string) {
    const appointment = await this.prisma.appointment.findUnique({
      where: { id },
      include: {
        patient: { select: { id: true, name: true } },
        doctor: { select: { id: true, name: true } },
      },
    });
    if (!appointment) throw new NotFoundException('Appointment not found');

    // Only patient, doctor, or admin can view
    if (
      requesterRole === 'PATIENT' && appointment.patientId !== requesterId ||
      requesterRole === 'DOCTOR' && appointment.doctorId !== requesterId
    ) {
      throw new ForbiddenException('Not authorized to view this appointment');
    }
    return appointment;
  }

  // List appointments (by patient, doctor, or admin)
  async listAppointments(query: { patientId?: number; doctorId?: number }, requesterId: number, requesterRole: string) {
    // Patients can only list their own, doctors their own, admins can list all
    if (requesterRole === 'PATIENT' && query.patientId !== requesterId) {
      throw new ForbiddenException('Patients can only view their own appointments');
    }
    if (requesterRole === 'DOCTOR' && query.doctorId !== requesterId) {
      throw new ForbiddenException('Doctors can only view their own appointments');
    }

    return this.prisma.appointment.findMany({
      where: {
        ...(query.patientId ? { patientId: query.patientId } : {}),
        ...(query.doctorId ? { doctorId: query.doctorId } : {}),
      },
      orderBy: { date: 'desc' },
      include: {
        patient: { select: { id: true, name: true } },
        doctor: { select: { id: true, name: true } },
      },
    });
  }

  // Update appointment (status or reschedule)
  async updateAppointment(id: number, dto: UpdateAppointmentDto, requesterId: number, requesterRole: string) {
    const appointment = await this.prisma.appointment.findUnique({ where: { id } });
    if (!appointment) throw new NotFoundException('Appointment not found');

    // Only patient (for reschedule/cancel), doctor (for confirm/complete), or admin
    if (
      requesterRole === 'PATIENT' && appointment.patientId !== requesterId ||
      requesterRole === 'DOCTOR' && appointment.doctorId !== requesterId
    ) {
      throw new ForbiddenException('Not authorized to update this appointment');
    }

    // If rescheduling, check for overlap
    if (dto.date && dto.date !== appointment.date.toISOString()) {
      const overlap = await this.prisma.appointment.findFirst({
        where: {
          doctorId: appointment.doctorId,
          date: dto.date,
          status: { in: ['CONFIRMED', 'PENDING'] },
          NOT: { id },
        },
      });
      if (overlap) {
        throw new BadRequestException('Doctor already has an appointment at this time');
      }
    }

  return this.prisma.appointment.update({
    where: { id },
    data: {
      ...(dto.date ? { date: new Date(dto.date) } : {}),
      ...(dto.status !== undefined ? { status: dto.status } : {}), // ✅ fixed
    },

    });
  }
}