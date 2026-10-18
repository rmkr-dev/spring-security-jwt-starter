package io.github.rmkrdev.entra.security.autoconfigure.keyvault;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.ClassUtils;

import com.azure.core.credential.TokenCredential;

import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityAutoConfiguration;
import io.github.rmkrdev.entra.security.autoconfigure.EntraSecurityProperties;

/**
 * Registers the {@link KeyVaultCredentialFactory} behind {@code credential.type=key-vault-certificate}.
 * <p>
 * Active only when {@code azure-identity} and at least one of {@code azure-security-keyvault-secrets} or
 * {@code azure-security-keyvault-certificates} are on the classpath. Nothing is contacted until a credential
 * of that type is used.
 */
@AutoConfiguration(before = EntraSecurityAutoConfiguration.class)
@ConditionalOnClass(name = EntraKeyVaultAutoConfiguration.DEFAULT_AZURE_CREDENTIAL)
@Conditional(EntraKeyVaultAutoConfiguration.OnKeyVaultClientCondition.class)
@ConditionalOnProperty(prefix = EntraSecurityProperties.PREFIX, name = "enabled", havingValue = "true",
        matchIfMissing = true)
public class EntraKeyVaultAutoConfiguration {

    static final String DEFAULT_AZURE_CREDENTIAL = "com.azure.identity.DefaultAzureCredentialBuilder";
    static final String SECRET_CLIENT = "com.azure.security.keyvault.secrets.SecretClient";
    static final String CERTIFICATE_CLIENT = "com.azure.security.keyvault.certificates.CertificateClient";

    /** Name of an optional application bean that replaces DefaultAzureCredential for reading the vault. */
    public static final String TOKEN_CREDENTIAL_BEAN = "entraKeyVaultTokenCredential";

    @Bean
    @ConditionalOnMissingBean
    public KeyVaultCredentialFactory entraKeyVaultCredentialFactory(
            @Qualifier(TOKEN_CREDENTIAL_BEAN) ObjectProvider<TokenCredential> tokenCredential,
            ResourceLoader resourceLoader) {
        return new AzureKeyVaultCredentialFactory(tokenCredential.getIfAvailable(),
                ClassUtils.isPresent(SECRET_CLIENT, resourceLoader.getClassLoader()));
    }

    /** Matches when either Key Vault client library is present. */
    static class OnKeyVaultClientCondition extends SpringBootCondition {

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            ClassLoader loader = context.getClassLoader();
            if (ClassUtils.isPresent(SECRET_CLIENT, loader)) {
                return ConditionOutcome.match("found " + SECRET_CLIENT);
            }
            if (ClassUtils.isPresent(CERTIFICATE_CLIENT, loader)) {
                return ConditionOutcome.match("found " + CERTIFICATE_CLIENT);
            }
            return ConditionOutcome.noMatch("neither " + SECRET_CLIENT + " nor " + CERTIFICATE_CLIENT + " found");
        }
    }
}
