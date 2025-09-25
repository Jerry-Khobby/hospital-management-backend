# Hospital Management System

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="NestJS Logo" /></a>
</p>

A scalable backend API for hospital management, built with [NestJS](https://nestjs.com/), [Prisma ORM](https://www.prisma.io/), PostgreSQL, and Redis.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Docker & Deployment](#docker--deployment)
- [CI/CD](#cicd)
- [Folder Structure](#folder-structure)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Features

- **User Authentication & Authorization** (JWT, role-based access)
- **User Management** (Admin, Doctor, Nurse, Patient, Pharmacist)
- **Patient Records** (CRUD, optimistic concurrency)
- **Appointments & Prescriptions**
- **Caching** (Redis for performance)
- **API Documentation** (Swagger)
- **Dockerized for easy deployment**
- **CI/CD with GitHub Actions**

---

## Tech Stack

- **NestJS** (TypeScript)
- **Prisma ORM**
- **PostgreSQL** (database)
- **Redis** (cache)
- **Swagger** (API docs)
- **Docker & Docker Compose**
- **GitHub Actions** (CI/CD)

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Jerry-Khobby/hospital-management.git
cd hospital-management
```

### 2. Install dependencies

```bash
npm install
```

### 3. Set up environment variables

Create a `.env` file in the root directory:

```env
POSTGRES_DB=your_db
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_password
DATABASE_URL=postgresql://your_user:your_password@localhost:5432/your_db
JWT_SECRET=your_jwt_secret
REDIS_URL=redis://localhost:6379
```

### 4. Run database migrations

```bash
npx prisma migrate dev
```

### 5. Start the application

```bash
# Development
npm run start:dev

# Production
npm run build
npm run start:prod
```

### 6. Run with Docker

```bash
docker-compose up --build
```

---

## API Documentation

Swagger docs are available at [http://localhost:3333/api](http://localhost:3333/api) when the app is running.

---

## Testing

```bash
# Unit tests
npm run test

# End-to-end tests
npm run test:e2e

# Test coverage
npm run test:cov
```

---

## Docker & Deployment

- The project includes a `Dockerfile` and `docker-compose.yml` for easy containerized setup.
- Services: backend (NestJS), PostgreSQL, Redis.
- See [docker-compose.yml](./docker-compose.yml) for configuration.

---

## CI/CD

This project uses GitHub Actions for continuous integration.  
See `.github/workflows/ci.yml` for details.

---

## Folder Structure

```
src/
  auth/         # Authentication & authorization
  users/        # User management
  patients/     # Patient records
  appointments/ # Appointments
  prescriptions/# Prescriptions
  prisma/       # Prisma schema
  redis/        # Redis cache integration
  app.module.ts # Main NestJS module
```

---

## Contributing

Feel free to open issues or submit PRs for improvements and new features!

---

## License

MIT

---

## Author

- **Jerry-Khobby** ([GitHub](https://github.com/Jerry-Khobby))
- **Email:** jerrymardeburg@gmail.com
