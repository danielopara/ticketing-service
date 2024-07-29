package com.projects.Ticketing.service.email;

import com.projects.Ticketing.model.Ticket;
import com.projects.Ticketing.repository.TicketRepository;
import jakarta.mail.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Properties;


@Service
public class EmailService {
    @Value("${spring.mail.host}")
    private String mailHost;

    @Value("${spring.mail.username}")
    private String mailUsername;

    @Value("${spring.mail.password}")
    private String mailPassword;

    private final TicketRepository ticketRepository;

    public EmailService(TicketRepository ticketRepository) {
        this.ticketRepository = ticketRepository;
    }


    public void checksForNewTickets(){
        try{
            Properties properties = new Properties();
            properties.put("mail.store.protocol", "imaps");
            Session session = Session.getInstance(properties, null);
            Store store = session.getStore("imaps");
            store.connect(mailHost, mailUsername, mailPassword);

            Folder inbox = store.getFolder("INBOX");
            inbox.open(Folder.READ_ONLY);


            Message[] messages = inbox.getMessages();
            for (Message message : messages) {
                if (message.getSubject().startsWith("[TICKET]")) {
                    String subject = message.getSubject();
                    String content = message.getContent().toString();

                    Ticket ticket = new Ticket();
                    ticket.setSubject(subject);
                    ticket.setContent(content);
                    ticketRepository.save(ticket);
                }
            }

            inbox.close(false);
            store.close();

        } catch (MessagingException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
