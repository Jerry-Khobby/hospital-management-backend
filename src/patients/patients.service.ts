import {
  Injectable,
  ConflictException,
  BadRequestException,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as crypto from 'crypto';

@Injectable()
export class PatientService {
  private readonly logger = new Logger(PatientService.name);

  // rate limiting configuration
  private readonly createRateLimitWindowMs = 60 * 1000; // 1 min
  private readonly createMaxRequests = 10; // max 10 per window
  private readonly lockTTL = 5 * 1000; // 5 seconds

  // encryption setup
  private readonly encryptionKey: Buffer;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
  ) {
    // setup encryption key
    const keyEnv = process.env.CONTACT_ENCRYPTION_KEY;
    if (!keyEnv) {
      this.logger.warn(
        'CONTACT_ENCRYPTION_KEY not set in env. Using insecure fallback key.',
      );
      this.encryptionKey = crypto.randomBytes(32); // fallback random key
    } else {
      this.encryptionKey =
        Buffer.from(keyEnv, 'base64').length === 32
          ? Buffer.from(keyEnv, 'base64')
          : Buffer.from(keyEnv, 'utf8');

      if (this.encryptionKey.length !== 32) {
        this.logger.error(
          'CONTACT_ENCRYPTION_KEY must be 32 bytes (base64 or utf8)',
        );
        this.encryptionKey = crypto.randomBytes(32); // fallback
      }
    }
  }

  //--------------------Helper Methods---------------------------------
  private async acquireLock(
    lockKey: string,
    ttl = this.lockTTL,
  ): Promise<boolean> {
    const existing = await this.cacheManager.get(lockKey);
    if (existing) return false;

    try {
      // pass TTL as number (in seconds)
      await this.cacheManager.set(lockKey, '1', Math.ceil(ttl / 1000));
      return true;
    } catch (err: any) {
      this.logger.warn(`Lock acquisition failed for ${lockKey}: ${err.message}`);
      return false;
    }
  }

  private async releaseLock(lockKey: string): Promise<void> {
    try {
      await this.cacheManager.del(lockKey);
    } catch (err: any) {
      this.logger.warn(`Lock release failed for ${lockKey}: ${err.message}`);
    }
  }

  private sanitizeName(name: string): string {
    if (!name) return name;
    // Remove control characters and trim whitespace
    return name.trim().replace(/[\x00-\x1F\x7F]/g, '');
  }

  private validateGender(gender?: string) {
    if (!gender) return; // allow optional
    const allowed = ['male', 'female', 'other'];
    if (!allowed.includes(gender.toLowerCase())) {
      throw new BadRequestException(
        `gender must be one of: ${allowed.join(', ')}`,
      );
    }
  }

  private encryptContactInfo(plain: string): string {
    if (!plain) return '';
    if (!this.encryptionKey) return plain; // fallback when encryption disabled

    try {
      // AES-256-GCM encryption
      const iv = crypto.randomBytes(12); // 96-bit IV for GCM
      const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        this.encryptionKey,
        iv,
      );
      const encrypted = Buffer.concat([
        cipher.update(plain, 'utf8'),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      // Combine IV + tag + encrypted data and encode as base64
      return Buffer.concat([iv, tag, encrypted]).toString('base64');
    } catch (err) {
      this.logger.error('Encryption failed', err);
      throw new InternalServerErrorException('Failed to encrypt contact info');
    }
  }

  private decryptContactInfo(ciphertextB64: string): string {
    if (!ciphertextB64) return '';
    if (!this.encryptionKey) return ciphertextB64;

    try {
      const data = Buffer.from(ciphertextB64, 'base64');
      const iv = data.slice(0, 12);
      const tag = data.slice(12, 28);
      const encrypted = data.slice(28);

      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.encryptionKey,
        iv,
      );
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ]);

      return decrypted.toString('utf8');
    } catch (err) {
      this.logger.error('Decryption failed', err);
      return '[DECRYPTION_ERROR]';
    }
  }

  private buildPatientCacheKey(id: number) {
    return `patient:${id}`;
  }

  private buildPatientListCacheKey(query: Record<string, any>) {
    return `patients:list:${JSON.stringify(query)}`;
  }

  //====================PATIENT OPERATIONS====================
  /**
   * CREATE PATIENT
   * Only Admins and Doctors can create patients
   * Includes rate limiting, duplicate prevention, and encryption
   */
  async createPatient(params: {
    name: string;
    age: number;
    gender?: string;
    contactInfo?: string;
    createdById: number;
  }): Promise<{ patient: any }> {
    const { name, age, gender, contactInfo, createdById } = params;

    // Input validation
    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      throw new BadRequestException('Name must be at least 2 characters long');
    }
    if (!Number.isInteger(age) || age < 0 || age > 150) {
      throw new BadRequestException('Age must be between 0 and 150');
    }
    this.validateGender(gender);

    const sanitizedName = this.sanitizeName(name);

    // Rate limiting per creator
    const rateKey = `create_patient_rate:${createdById}:${Math.floor(
      Date.now() / this.createRateLimitWindowMs,
    )}`;
    const attempts = (await this.cacheManager.get<number>(rateKey)) || 0;

    if (attempts >= this.createMaxRequests) {
      throw new ServiceUnavailableException(
        'Rate limit exceeded for creating patients',
      );
    }

    // Increment rate limit counter
    await this.cacheManager.set(
      rateKey,
      attempts + 1,
      Math.ceil(this.createRateLimitWindowMs / 1000),
    );

    // Verify creator exists and has proper role
    const creator = await this.prisma.user.findUnique({
      where: { id: createdById },
      select: { id: true, role: true, name: true },
    });

    if (!creator) {
      throw new NotFoundException('Creator not found');
    }

    if (!['ADMIN', 'DOCTOR'].includes(creator.role)) {
      throw new ForbiddenException(
        'Only Admins or Doctors can create patient records',
      );
    }

    // Acquire lock to prevent race conditions
    const lockKey = `lock:create_patient:${createdById}:${sanitizedName}:${age}`;
    const lockAcquired = await this.acquireLock(lockKey);

    if (!lockAcquired) {
      throw new ServiceUnavailableException(
        'Could not acquire lock, please try again',
      );
    }

    try {
      // Check for duplicate patients
      const whereConditions: any[] = [{ name: sanitizedName }];
      if (contactInfo) {
        whereConditions.push({
          contactInfo: this.encryptContactInfo(contactInfo),
        });
      }

      const existingPatient = await this.prisma.patient.findFirst({
        where: { OR: whereConditions },
        select: { id: true, name: true },
      });

      if (existingPatient) {
        throw new ConflictException(
          'Patient with this name or contact info already exists',
        );
      }

      // Encrypt contact info
      const encryptedContact = contactInfo
        ? this.encryptContactInfo(contactInfo)
        : null;

      // Create patient in transaction
      const patient = await this.prisma.$transaction(async (tx) => {
        const createdPatient = await tx.patient.create({
          data: {
            name: sanitizedName,
            age,
            gender: gender ? gender.toLowerCase() : '', // safe optional
            contactInfo: encryptedContact,
            createdById,
          },
          include: {
            createdBy: {
              select: { id: true, name: true, role: true },
            },
          },
        });

        // Future: Add audit log entry here
        // await tx.auditLog.create({...})

        return createdPatient;
      });

      // Cache the newly created patient
      try {
        const patientForCache = {
          ...patient,
          contactInfo: contactInfo, // Store decrypted version in cache
        };
        await this.cacheManager.set(
          this.buildPatientCacheKey(patient.id),
          patientForCache,
          300, // 5 minutes
        );
      } catch (cacheErr: any) {
        this.logger.debug(
          `Failed to cache patient ${patient.id}: ${cacheErr.message}`,
        );
      }

      // Return patient with decrypted contact info
      return {
        patient: {
          ...patient,
          contactInfo: contactInfo,
        },
      };
    } catch (error: any) {
      // Re-throw known exceptions
      if (
        error instanceof BadRequestException ||
        error instanceof ConflictException ||
        error instanceof NotFoundException ||
        error instanceof ForbiddenException
      ) {
        throw error;
      }

      this.logger.error('createPatient error', error);
      throw new InternalServerErrorException('Failed to create patient');
    } finally {
      // Always release the lock
      await this.releaseLock(lockKey);
    }
  }
}
