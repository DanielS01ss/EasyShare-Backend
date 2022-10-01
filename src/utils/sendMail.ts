import nodemailer from 'nodemailer';
import { GOOGLE_ACC_PASS } from './envConstants';

async function sendMail(): Promise<void> {
  const client = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: 'danystanculescu@gmail.com',
      pass: GOOGLE_ACC_PASS,
    },
  });

  await client.sendMail({
    from: 'danystanculescu@gmail.com',
    to: 'thegamerdany01@gmail.com',
    subject: 'Test Email',
    text: 'This is just a test!',
  });
}

export default sendMail;
