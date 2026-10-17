package io.github.rmkrdev.entra.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.rmkrdev.entra.security.EnableEntraSecurity;

@SpringBootApplication
@EnableEntraSecurity
public class SampleApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleApiApplication.class, args);
    }
}
