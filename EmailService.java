package com.monitor.service;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.Properties;

public class EmailService {

    private static final String EMAIL =
            "yourgmail@gmail.com";

    private static final String APP_PASSWORD =
            "YOUR_APP_PASSWORD";

    public static void sendRecoveryMail(
            String receiverEmail,
            String resetLink) throws Exception {

        Properties props = new Properties();

        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(
                props,
                new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(
                                EMAIL,
                                APP_PASSWORD
                        );
                    }
                });

        Message message = new MimeMessage(session);

        message.setFrom(new InternetAddress(EMAIL));

        message.setRecipients(
                Message.RecipientType.TO,
                InternetAddress.parse(receiverEmail)
        );

        message.setSubject("Password Recovery");

        messamessage = new MimeMessage(session);

        message.setFrom(new InternetAddress(EMAIL));

        message.setRecipients(
                Message.RecipientType.TO,
                InternetAddress.parse(receiverEmail)
        );

        message.setSubject("Password Recovery");

        message.setText(
                "Website Monitoring System\n\n" +
                "Click this link to reset password:\n\n" +
                resetLink
        );

        Transport.send(message);

        System.out.println("Recovery Email Sent Successfully");
    }
}