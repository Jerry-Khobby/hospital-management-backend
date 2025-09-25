import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  ParseIntPipe,
  UseGuards,
  Req,
  HttpStatus,
  HttpCode,
  ValidationPipe,
} from '@nestjs/common';



import { PatientService } from './patients.service';
import { ApiTags,ApiOperation,ApiResponse } from '@nestjs/swagger';



@ApiTags('patients')
@Controller('patients')
export class PatientController {
  constructor(private patientService: PatientService) {} 
  
  
   /**
   * CREATE PATIENT
   * POST /patients
   * Only Admins and Doctors can create patients
   */
  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create a new patient' })
  @ApiResponse({ status: 201, description: 'Patient created successfully.' })
  async createPatient(@Body(new ValidationPipe({ whitelist: true })) createPatientDto: any) {
    return this.patientService.createPatient(createPatientDto);
  }


  /**
   * LIST PATIENTS
   * GET /patients
   * Supports pagination and search
   */ 
  @Get()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get a list of patients' })
  @ApiResponse({ status: 200, description: 'List of patients retrieved successfully.' })
  async getPatients(@Query(new ValidationPipe({ transform: true })) query: any) {
    return this.patientService.listPatients(query);
  }



 /**
   * GET SINGLE PATIENT
   * GET /patients/:id
   */

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get a patient by ID' })
  @ApiResponse({ status: 200, description: 'Patient retrieved successfully.' })
  async getPatientById(
    @Param('id', ParseIntPipe) id: number,
    @Req() req: any
  ) {
    const requesterId = req.user?.id;
    const requesterRole = req.user?.role;
    return this.patientService.getPatient({
      requesterId,
      requesterRole,
      patientId: id,
    });
  }


  /**
   * UPDATE PATIENT
   * PUT /patients/:id
   * Only Admins and Doctors can update
   */
  @Put(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update a patient by ID' })
  @ApiResponse({ status: 200, description: 'Patient updated successfully.' })
  async updatePatient(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ValidationPipe({ whitelist: true })) updatePatientDto: any, 
    @Req() req: any
  ) {
    const requesterId = req.user?.id;
    const requesterRole = req.user?.role;
    return this.patientService.updatePatient({
      requesterId,
      requesterRole,
      patientId: id,
      data: updatePatientDto,
    });
  } 


    /**
   * DELETE PATIENT
   * DELETE /patients/:id
   * Only Admins can delete
   */
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a patient by ID' })  
  @ApiResponse({ status: 204, description: 'Patient deleted successfully.' })
  async deletePatient(
    @Param('id', ParseIntPipe) id: number,
    @Req() req: any
  ) {
    const requesterId = req.user?.id;
    const requesterRole = req.user?.role;
    return this.patientService.deletePatient({
      requesterId,
      requesterRole,
      patientId: id,
    });
  }


}