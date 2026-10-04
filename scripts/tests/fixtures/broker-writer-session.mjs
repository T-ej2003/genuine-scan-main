import { createHash } from 'node:crypto';
export const writerAccessKeyId = 'ASIA' + 'A'.repeat(16);
export const writerSession = { accessKeyIdSha256: createHash('sha256').update(writerAccessKeyId).digest('hex'),
  callerArn: 'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/operator', callerUserId: 'AROAEXAMPLE:operator',
  eventId: '11111111-1111-4111-8111-111111111111', issuedAt: '2026-10-04T00:00:00.000Z', expiresAt: '2026-10-04T01:00:00.000Z' };
export function writerIssuance() {
  return { eventID: writerSession.eventId, eventTime: writerSession.issuedAt, eventName: 'AssumeRole', eventSource: 'sts.amazonaws.com',
    recipientAccountId: '368992683803', awsRegion: 'eu-west-2',
    requestParameters: { roleArn: 'arn:aws:iam::368992683803:role/mscqr-production-release-deployer', roleSessionName: 'operator', durationSeconds: 3600 },
    responseElements: { assumedRoleUser: { arn: writerSession.callerArn, assumedRoleId: writerSession.callerUserId },
      credentials: { accessKeyId: writerAccessKeyId, expiration: writerSession.expiresAt } } };
}
