import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  Req,
  UseGuards,
  ParseIntPipe,
} from '@nestjs/common';
import { PrescriptionsService } from './prescriptions.service';
import { CreatePrescriptionDto } from './dto/prescriptions.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
//import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { RolesGuard } from 'src/auth/roles.guard';

@ApiTags('prescriptions')
@Controller('prescriptions')
@UseGuards(RolesGuard)
export class PrescriptionsController {
  constructor(private readonly prescriptionsService: PrescriptionsService) {}

  /**
   * Create a prescription for a patient (Doctor only)
   */
  @Post()
  @ApiOperation({ summary: 'Create a prescription for a patient' })
  @ApiResponse({ status: 201, description: 'Prescription created successfully.' })
  async createPrescription(
    @Body() dto: CreatePrescriptionDto,
    @Req() req: any,
  ) {
    return this.prescriptionsService.createPrescription(dto, req.user.id, req.user.role);
  }

  /**
   * Get a prescription by ID (Doctor, Patient (self), Pharmacist)
   */
  @Get(':id')
  @ApiOperation({ summary: 'Get a prescription by ID' })
  @ApiResponse({ status: 200, description: 'Prescription retrieved successfully.' })
  async getPrescription(
    @Param('id', ParseIntPipe) id: number,
    @Req() req: any,
  ) {
    return this.prescriptionsService.getPrescription(id, req.user.id, req.user.role);
  }

  /**
   * Get all prescriptions for a patient
   */
  @Get('patient/:patientId')
  @ApiOperation({ summary: 'Get all prescriptions for a patient' })
  @ApiResponse({ status: 200, description: 'Prescriptions retrieved successfully.' })
  async getPrescriptionsForPatient(
    @Param('patientId', ParseIntPipe) patientId: number,
    @Req() req: any,
  ) {
    return this.prescriptionsService.getPrescriptionsForPatient(patientId, req.user.id, req.user.role);
  }
}