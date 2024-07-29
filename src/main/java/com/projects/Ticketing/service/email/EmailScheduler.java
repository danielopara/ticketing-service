package com.projects.Ticketing.service.email;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class EmailScheduler {
    private final EmailService emailService;

    public EmailScheduler(EmailService emailService) {
        this.emailService = emailService;
    }

    @Scheduled(fixedRate = 60000)
    public void checkEmails(){
        emailService.checksForNewTickets();
    }
}
