import { User, Licensee, QRCode, Batch, Manufacturer, AuditLog } from '@/types';

// Mock Users
export const mockUsers: User[] = [
  {
    id: '1',
    email: 'admin@mscqr.com',
    name: 'Super Admin',
    role: 'super_admin',
    createdAt: '2024-01-01T00:00:00Z',
  },
  {
    id: '2',
    email: 'licensee@alphaproducts.com',
    name: 'Alpha Products Admin',
    role: 'licensee_admin',
    licenseeId: 'lic-1',
    createdAt: '2024-01-15T00:00:00Z',
  },
  {
    id: '3',
    email: 'manufacturer@betamfg.com',
    name: 'Beta Manufacturing',
    role: 'manufacturer',
    licenseeId: 'lic-1',
    createdAt: '2024-02-01T00:00:00Z',
  },
];

// Mock Licensees
export const mockLicensees: Licensee[] = [
  {
    id: 'lic-1',
    name: 'Alpha Products Inc.',
    prefix: 'A',
    rangeStart: 1,
    rangeEnd: 150000,
    location: 'New York, USA',
    website: 'https://alphaproducts.com',
    createdAt: '2024-01-15T00:00:00Z',
    isActive: true,
  },
  {
    id: 'lic-2',
    name: 'Beta Industries',
    prefix: 'B',
    rangeStart: 1,
    rangeEnd: 100000,
    location: 'London, UK',
    website: 'https://betaindustries.co.uk',
    createdAt: '2024-02-01T00:00:00Z',
    isActive: true,
  },
  {
    id: 'lic-3',
    name: 'Gamma Solutions',
    prefix: 'X1',
    rangeStart: 1,
    rangeEnd: 50000,
    location: 'Tokyo, Japan',
    website: 'https://gamma.jp',
    createdAt: '2024-03-01T00:00:00Z',
    isActive: false,
  },
];

// Mock Manufacturers
export const mockManufacturers: Manufacturer[] = [
  {
    id: 'mfg-1',
    name: 'Beta Manufacturing Co.',
    licenseeId: 'lic-1',
    location: 'Chicago, USA',
    email: 'contact@betamfg.com',
    createdAt: '2024-02-01T00:00:00Z',
    isActive: true,
  },
  {
    id: 'mfg-2',
    name: 'Delta Printers',
    licenseeId: 'lic-1',
    location: 'Los Angeles, USA',
    email: 'info@deltaprinters.com',
    createdAt: '2024-02-15T00:00:00Z',
    isActive: true,
  },
  {
    id: 'mfg-3',
    name: 'Epsilon Labels',
    licenseeId: 'lic-2',
    location: 'Manchester, UK',
    email: 'hello@epsilonlabels.co.uk',
    createdAt: '2024-03-01T00:00:00Z',
    isActive: true,
  },
];

// Mock Batches
export const mockBatches: Batch[] = [
  {
    id: 'batch-1',
    name: 'Batch 001 - Spring Collection',
    licenseeId: 'lic-1',
    manufacturerId: 'mfg-1',
    qrCodeStart: 'A0000000001',
    qrCodeEnd: 'A0000010000',
    qrCount: 10000,
    status: 'confirmed',
    createdAt: '2024-02-01T00:00:00Z',
    assignedAt: '2024-02-05T00:00:00Z',
    confirmedAt: '2024-02-10T00:00:00Z',
  },
  {
    id: 'batch-2',
    name: 'Batch 002 - Summer Line',
    licenseeId: 'lic-1',
    manufacturerId: 'mfg-2',
    qrCodeStart: 'A0000010001',
    qrCodeEnd: 'A0000025000',
    qrCount: 15000,
    status: 'assigned',
    createdAt: '2024-03-01T00:00:00Z',
    assignedAt: '2024-03-05T00:00:00Z',
  },
  {
    id: 'batch-3',
    name: 'Batch 003 - Reserved',
    licenseeId: 'lic-1',
    qrCodeStart: 'A0000025001',
    qrCodeEnd: 'A0000050000',
    qrCount: 25000,
    status: 'created',
    createdAt: '2024-03-15T00:00:00Z',
  },
];

// Generate mock QR codes
export const generateMockQRCodes = (licensee: Licensee, count: number = 100): QRCode[] => {
  const codes: QRCode[] = [];
  const statuses: Array<{ status: QRCode['status']; weight: number }> = [
    { status: 'dormant', weight: 40 },
    { status: 'allocated', weight: 30 },
    { status: 'printed', weight: 20 },
    { status: 'scanned', weight: 10 },
  ];

  for (let i = 0; i < count; i++) {
    const num = licensee.rangeStart + i;
    const code = `${licensee.prefix}${num.toString().padStart(10, '0')}`;
    
    // Weighted random status
    const rand = Math.random() * 100;
    let cumulative = 0;
    let status: QRCode['status'] = 'dormant';
    for (const s of statuses) {
      cumulative += s.weight;
      if (rand < cumulative) {
        status = s.status;
        break;
      }
    }

    codes.push({
      id: `qr-${licensee.id}-${i}`,
      code,
      licenseeId: licensee.id,
      status,
      createdAt: '2024-01-01T00:00:00Z',
      scanCount: status === 'scanned' ? Math.floor(Math.random() * 10) + 1 : 0,
    });
  }

  return codes;
};

// Mock Audit Logs
export const mockAuditLogs: AuditLog[] = [
  {
    id: 'log-1',
    userId: '1',
    userName: 'Super Admin',
    action: 'CREATE_LICENSEE',
    details: 'Created licensee: Alpha Products Inc.',
    timestamp: '2024-01-15T10:30:00Z',
  },
  {
    id: 'log-2',
    userId: '2',
    userName: 'Alpha Products Admin',
    action: 'CREATE_BATCH',
    details: 'Created batch: Batch 001 - Spring Collection',
    timestamp: '2024-02-01T14:20:00Z',
  },
  {
    id: 'log-3',
    userId: '2',
    userName: 'Alpha Products Admin',
    action: 'ASSIGN_BATCH',
    details: 'Assigned batch to manufacturer: Beta Manufacturing Co.',
    timestamp: '2024-02-05T09:15:00Z',
  },
  {
    id: 'log-4',
    userId: '3',
    userName: 'Beta Manufacturing',
    action: 'CONFIRM_PRINT',
    details: 'Confirmed printing of batch: Batch 001 - Spring Collection',
    timestamp: '2024-02-10T16:45:00Z',
  },
  {
    id: 'log-5',
    userId: '1',
    userName: 'Super Admin',
    action: 'CREATE_LICENSEE',
    details: 'Created licensee: Beta Industries',
    timestamp: '2024-02-01T11:00:00Z',
  },
];
