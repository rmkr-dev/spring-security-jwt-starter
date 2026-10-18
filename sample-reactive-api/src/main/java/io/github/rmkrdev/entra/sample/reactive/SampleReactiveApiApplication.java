package io.github.rmkrdev.entra.sample.reactive;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.rmkrdev.entra.security.EnableEntraSecurity;

@SpringBootApplication
@EnableEntraSecurity
public class SampleReactiveApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleReactiveApiApplication.class, args);
    }
}
