import { bodyParser } from '@/utils/bodyParser';
import { response } from '@/utils/response';
import type { APIGatewayProxyEventV2 } from 'aws-lambda';

import { ConfirmForgotPasswordCommand } from '@aws-sdk/client-cognito-identity-provider';
import { cognitoClient } from '@/libs/cognitoClients';

export async function handler(event: APIGatewayProxyEventV2) {
  try {
    const { email, code, newPassword } = bodyParser(event.body ?? '');

    const command = new ConfirmForgotPasswordCommand({
      ClientId: process.env.COGNITO_CLIENT_ID,
      Username: email,
      ConfirmationCode: code,
      Password: newPassword
    });

    await cognitoClient.send(command);

    return response(204);
  } catch (error) {
    return response(500, {
      error: 'Internal server error'
    });
  }
}
