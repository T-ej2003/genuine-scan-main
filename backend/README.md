# Authentic QR Backend

A Node.js + Express + TypeScript backend with PostgreSQL and Prisma ORM for the Authentic QR Licensee Platform.

## Prerequisites

- Node.js 18+ 
- PostgreSQL 14+
- npm or yarn

## Quick Start

### 1. Install dependencies

```bash
cd backend
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your database credentials
```

### 3. Setup database

```bash
# Generate Prisma client
npm run prisma:generate

# Run migrations
npm run prisma:migrate

# Seed with demo data
npm run prisma:seed
```

### 4. Start the server

```bash
# Development mode (with hot reload)
npm run dev

# Production mode
npm run build
npm start
```

Server runs at `http://localhost:3001`

### Customer Identity Env (Optional but Recommended)

- `SESSION_SECRET`
- `GOOGLE_CLIENT_ID`
- `CUSTOMER_OTP_TTL_MINUTES`
- `CUSTOMER_OTP_MAX_ATTEMPTS`
- `CUSTOMER_OTP_RATE_WINDOW_MINUTES`
- `CUSTOMER_OTP_RATE_MAX_PER_WINDOW`

## API Endpoints

### Public

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/google` | Customer Google sign-in (ID token) |
| POST | `/api/auth/email/request-otp` | Customer email OTP request |
| POST | `/api/auth/email/verify-otp` | Customer email OTP verify |
| GET | `/api/me` | Get current customer session |
| GET | `/api/verify/:code` | Public QR verification |
| POST | `/api/scan/:code` | Record scan + classify risk by code |
| GET | `/api/scan?t=...` | Record scan + classify risk by signed token |
| POST | `/api/claim/:code` | Claim ownership for signed-in customer |
| POST | `/api/fraud-report` | Create fraud report + incident ticket |

### Authenticated

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/api/auth/me` | Any | Get current user |

### Super Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/licensees` | Create licensee |
| GET | `/api/licensees` | List all licensees |
| GET | `/api/licensees/:id` | Get licensee details |
| PATCH | `/api/licensees/:id` | Update licensee |
| POST | `/api/qr/ranges/allocate` | Allocate QR range |
| POST | `/api/users` | Create user |
| GET | `/api/audit/logs` | View audit logs |

### Licensee Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/qr/batches` | Create batch |
| GET | `/api/qr/batches` | List batches |
| POST | `/api/qr/batches/:id/assign-manufacturer` | Assign manufacturer |
| GET | `/api/qr/codes` | List QR codes |
| GET | `/api/qr/stats` | Get QR statistics |
| GET | `/api/manufacturers` | List manufacturers |

### Manufacturer

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/qr/:code/mark-printed` | Mark batch as printed |
| GET | `/api/qr/batches` | View assigned batches |

## Demo Credentials

| Role | Email | Password |
|------|-------|----------|
| Super Admin | admin@authenticqr.com | admin123 |
| Licensee Admin | admin@acme.com | licensee123 |
| Licensee Admin | admin@beta.com | licensee123 |
| Manufacturer | factory1@acme.com | manufacturer123 |

## QR Status Lifecycle

```
DORMANT → ACTIVE → ALLOCATED → PRINTED → SCANNED
                                  ↑
                           (locked - no reversal)
```

## Architecture

```
backend/
├── prisma/
│   ├── schema.prisma    # Database schema
│   └── seed.ts          # Demo data seeder
├── src/
│   ├── config/          # Database configuration
│   ├── controllers/     # Route handlers
│   ├── middleware/      # Auth, RBAC, tenant isolation
│   ├── routes/          # API route definitions
│   ├── services/        # Business logic
│   ├── types/           # TypeScript definitions
│   └── index.ts         # Server entry point
└── .env.example         # Environment template
```

## Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run prisma:generate
RUN npm run build
EXPOSE 3001
CMD ["npm", "start"]
```

## License

MIT
