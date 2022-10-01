import nodemailer from 'nodemailer';
import { GOOGLE_ACC_PASS } from './envConstants';

async function sendMail(email: string, text: string, subject: string): Promise<void> {
  const client = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'danystanculescu@gmail.com',
      pass: GOOGLE_ACC_PASS,
    },
  });

  await client.sendMail({
    from: 'danystanculescu@gmail.com',
    to: email,
    subject,
    text,
  });
}

export default sendMail;
