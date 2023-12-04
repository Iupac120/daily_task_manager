
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();




export async function sendMail(email,subject,message) {
  const transporter = nodemailer.createTransport({
    service: process.env.NODEMAILER_SERVICE,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });
  
  const info = await transporter.sendMail({
    from: `"Austech" <${process.env.NODEMAILER_USER}>`,
    to: email,
    subject: subject,
    html: message,
  });
  console.log(info)
}
