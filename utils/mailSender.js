const nodemailer = require("nodemailer");

const mailSender = async (email, title, body) => {
    try {
        // Create transporter
        let transporter = nodemailer.createTransport({
            host: process.env.MAIL_HOST,
            port: process.env.MAIL_PORT,
            secure: true, // true for 465, false for other ports
            auth: {
                user: process.env.MAIL_USER,
                pass: process.env.MAIL_PASS,
            },
        });

        // Verify connection configuration
        await transporter.verify((error, success) => {
            if (error) {
                console.log("Error verifying transporter:", error);
                throw error;
            } else {
                console.log("Server is ready to take our messages");
            }
        });

        // Send mail
        let info = await transporter.sendMail({
            from: `"StudyNotion" <${process.env.MAIL_USER}>`, // More professional format
            to: email,
            subject: title,
            html: body,
        });

        console.log("Message sent: %s", info.messageId);
        return info;
    } catch (error) {
        console.error("Error in mailSender:", error.message);
        throw error; // Re-throw the error so the caller can handle it
    }
};

module.exports = mailSender;