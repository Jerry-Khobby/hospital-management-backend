import { Controller, Post, Get, Patch, Param, Query, Body, Req, UseGuards } from '@nestjs/common';
import { AppointmentsService } from './appointments.service';
import { CreateAppointmentDto, UpdateAppointmentDto } from './dto/appointments.dto';
import { AuthMiddleware } from 'src/auth/jwt.strategy';
 // Assume you have a roles guard

import { RolesGuard } from 'src/auth/roles.guard';

//Api documentation to it 


@Controller('appointments')
@UseGuards(AuthMiddleware, RolesGuard)
export class AppointmentsController {
  constructor(private readonly appointmentsService: AppointmentsService) {}

  @Post()
  async bookAppointment(
    @Body() dto: CreateAppointmentDto,
    @Req() req: any,
  ) {
    return this.appointmentsService.createAppointment(dto, req.user.id, req.user.role);
  }

  @Get(':id')
  async getAppointment(
    @Param('id') id: number,
    @Req() req: any,
  ) {
    return this.appointmentsService.getAppointment(Number(id), req.user.id, req.user.role);
  }

  @Get()
  async listAppointments(
    @Query('patientId') patientId: number,
    @Query('doctorId') doctorId: number,
    @Req() req: any,
  ) {
    return this.appointmentsService.listAppointments(
      { patientId: patientId ? Number(patientId) : undefined, doctorId: doctorId ? Number(doctorId) : undefined },
      req.user.id,
      req.user.role,
    );
  }

  @Patch(':id')
  async updateAppointment(
    @Param('id') id: number,
    @Body() dto: UpdateAppointmentDto,
    @Req() req: any,
  ) {
    return this.appointmentsService.updateAppointment(Number(id), dto, req.user.id, req.user.role);
  }
}