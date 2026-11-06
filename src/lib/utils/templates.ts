export function resetPasswordTemplate(
  appName: string,
  resetUrl: URL,
  expiresInMinutes: number,
) {
  return `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Reset your password</title>
      </head>

      <body style="margin:0;padding:0;background-color:#f3f4f6;
                  font-family:Arial,Helvetica,sans-serif;color:#111827;">

        <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
              style="background-color:#f3f4f6;">
          <tr>
            <td align="center" style="padding:40px 16px;">

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
                    style="max-width:560px;background-color:#ffffff;
                            border:1px solid #e5e7eb;border-radius:12px;">

                <tr>
                  <td style="padding:32px 32px 20px;
                            font-size:18px;font-weight:bold;color:#2563eb;">
                    ${appName}
                  </td>
                </tr>

                <tr>
                  <td style="padding:0 32px;">
                    <h1 style="margin:0 0 16px;font-size:26px;
                              line-height:1.3;color:#111827;">
                      Reset your password
                    </h1>

                    <p style="margin:0;font-size:16px;line-height:1.7;color:#4b5563;">
                      to reset your password.
                      Click the button below to choose a new one.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td align="center" style="padding:28px 32px;">
                    <table role="presentation" cellpadding="0" cellspacing="0">
                      <tr>
                        <td align="center" bgcolor="#2563eb"
                            style="border-radius:8px;">
                          <a href="${resetUrl}"
                            style="display:inline-block;padding:16px 28px;
                                    border:1px solid #2563eb;border-radius:8px;
                                    font-size:16px;font-weight:bold;
                                    color:#ffffff;text-decoration:none;">
                            Reset password
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <tr>
                  <td style="padding:0 32px 24px;">
                    <p style="margin:0 0 16px;font-size:14px;
                              line-height:1.6;color:#4b5563;">
                      This link expires in <strong>${expiresInMinutes} minutes</strong>.
                    </p>

                    <p style="margin:0;font-size:14px;line-height:1.6;color:#6b7280;">
                      If you did not request a password reset, you can safely
                      ignore this email. Your password has not been changed.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td style="padding:24px 32px;border-top:1px solid #e5e7eb;">
                    <p style="margin:0 0 8px;font-size:12px;
                              line-height:1.6;color:#6b7280;">
                      Button not working? Copy and paste this link into your browser:
                    </p>

                    <a href="${resetUrl}"
                      style="font-size:12px;line-height:1.6;color:#2563eb;
                              word-break:break-all;">
                      ${resetUrl}
                    </a>
                  </td>
                </tr>

              </table>

              <p style="margin:20px 0 0;font-size:12px;color:#6b7280;">
                ${appName} &middot; Account security
              </p>

            </td>
          </tr>
        </table>
      </body>
    </html>
  `;
}
