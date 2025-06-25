import nodemailer from 'nodemailer';

const email = process.env.EMAIL_USER;
const password = process.env.EMAIL_PASS;

// Create a transporter object
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: email,
        pass: password
    }
});

// Util to send mail
export const sendMail = async ({ to, subject, html }) => {
    const mailOptions = {
        from: `"Sonexa" <${email}>`,
        to,
        subject,
        html
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        return info;

    } catch (error) {
        throw error;
    }
}

