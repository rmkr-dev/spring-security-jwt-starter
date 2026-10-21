package io.github.rmkrdev.entra.security.autoconfigure;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringBootVersion;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Stops startup with a clear message when the application runs a Spring Boot line this starter was not built for.
 * Without it, a Spring Boot 3.x or 4.0 application that picks up the 1.x starter fails later with a
 * {@code ClassNotFoundException} or {@code NoSuchMethodError} from deep inside the auto-configuration.
 *
 * <p>Registered in {@code META-INF/spring.factories}, so it runs before any auto-configuration class is loaded.
 * It only touches classes that exist on every Spring Boot line. Versions older than {@value #MIN_MAJOR}.{@value
 * #MIN_MINOR} fail; a newer minor or major logs one WARN because it has not been tested. An unknown version (for
 * example a repackaged Spring Boot jar without a manifest) is skipped. Turn the check off with
 * {@code entra.security.self-check.spring-boot-version=false}.
 */
public final class EntraSpringBootVersionCheck implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    /** The property that turns the check off. */
    public static final String ENABLED_PROPERTY = "entra.security.self-check.spring-boot-version";

    static final int MIN_MAJOR = 4;

    static final int MIN_MINOR = 1;

    private static final Pattern VERSION = Pattern.compile("^(\\d+)\\.(\\d+)");

    private static final Logger log = LoggerFactory.getLogger(EntraSpringBootVersionCheck.class);

    private final String bootVersion;

    public EntraSpringBootVersionCheck() {
        this(SpringBootVersion.getVersion());
    }

    EntraSpringBootVersionCheck(String bootVersion) {
        this.bootVersion = bootVersion;
    }

    @Override
    public void initialize(ConfigurableApplicationContext context) {
        if (!context.getEnvironment().getProperty(ENABLED_PROPERTY, Boolean.class, true)) {
            return;
        }
        switch (check(bootVersion)) {
            case TOO_OLD -> throw new IllegalStateException("entra-security " + starterVersion()
                    + " needs Spring Boot " + MIN_MAJOR + "." + MIN_MINOR + ".x but this application runs Spring Boot "
                    + bootVersion + ". Use entra-security 0.7.x on Spring Boot 3.x, or upgrade the application "
                    + "(see docs/upgrading.md). Set " + ENABLED_PROPERTY + "=false to skip this check.");
            case NEWER -> log.warn("entra-security {} is built and tested on Spring Boot {}.{}.x; this application runs "
                    + "Spring Boot {}. Check docs/compatibility.md before relying on it.", starterVersion(), MIN_MAJOR,
                    MIN_MINOR, bootVersion);
            default -> {
                // supported or unknown
            }
        }
    }

    /** The outcome for a Spring Boot version string. */
    enum Result {
        SUPPORTED, TOO_OLD, NEWER, UNKNOWN
    }

    static Result check(String version) {
        if (version == null) {
            return Result.UNKNOWN;
        }
        Matcher matcher = VERSION.matcher(version.trim());
        if (!matcher.find()) {
            return Result.UNKNOWN;
        }
        int major = Integer.parseInt(matcher.group(1));
        int minor = Integer.parseInt(matcher.group(2));
        if (major < MIN_MAJOR || (major == MIN_MAJOR && minor < MIN_MINOR)) {
            return Result.TOO_OLD;
        }
        if (major > MIN_MAJOR || minor > MIN_MINOR) {
            return Result.NEWER;
        }
        return Result.SUPPORTED;
    }

    private static String starterVersion() {
        String version = EntraSpringBootVersionCheck.class.getPackage().getImplementationVersion();
        return version != null ? version : "1.x";
    }
}
