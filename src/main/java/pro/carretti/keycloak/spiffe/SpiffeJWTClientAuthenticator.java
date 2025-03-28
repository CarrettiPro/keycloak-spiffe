package pro.carretti.keycloak.spiffe;

import jakarta.ws.rs.core.Response;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import static org.keycloak.models.TokenManager.DEFAULT_VALIDATOR;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;

public class SpiffeJWTClientAuthenticator extends JWTClientAuthenticator {

    public static final String PROVIDER_ID = "spiffe-jwt";
    private static final Logger LOG = Logger.getLogger(SpiffeJWTClientAuthenticator.class);

    private static final String OIDC_ISSUER = "oidc-issuer";
    private static final String TRUST_DOMAIN = "trust-domain";

    private String trustDomain;
    private String oidcIssuer;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        trustDomain = config.get(TRUST_DOMAIN, "example.org");
        oidcIssuer = config.get(OIDC_ISSUER, "https://oidc-discovery-provider.example.org");
    }

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        SpiffeJWTClientValidator validator = new SpiffeJWTClientValidator(context, getId());
        if (!validator.clientAssertionParametersValidation()) return;

        try {
            validator.readJws();
            if (!validator.validateClient()) return;
            if (!validator.validateSignatureAlgorithm()) return;

            RealmModel realm = validator.getRealm();
            ClientModel client = validator.getClient();
            JWSInput jws = validator.getJws();
            JsonWebToken token = validator.getToken();
            String clientAssertion = validator.getClientAssertion();

            // Get client key and validate signature
            PublicKey clientPublicKey = getSignatureValidationKey(client, context, jws);
            if (clientPublicKey == null) {
                // Error response already set to context
                return;
            }

            boolean signatureValid;
            try {
                JsonWebToken jwt = context.getSession().tokens().decodeClientJWT(clientAssertion, client, (jose, validatedClient) -> {
                    DEFAULT_VALIDATOR.accept(jose, validatedClient);
                    String signatureAlgorithm = jose.getHeader().getRawAlgorithm();
                    ClientSignatureVerifierProvider signatureProvider = context.getSession().getProvider(ClientSignatureVerifierProvider.class, signatureAlgorithm);
                    if (signatureProvider == null) {
                        throw new RuntimeException("Algorithm not supported");
                    }
                    if (!signatureProvider.isAsymmetricAlgorithm()) {
                        throw new RuntimeException("Algorithm is not asymmetric");
                    }
                }, JsonWebToken.class);
                signatureValid = jwt != null;
            } catch (RuntimeException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                throw new RuntimeException("Signature on JWT token failed validation", cause);
            }
            if (!signatureValid) {
                throw new RuntimeException("Signature on JWT token failed validation");
            }

            // Allow both "issuer" or "token-endpoint" as audience
            List<String> expectedAudiences = getExpectedAudiences(context, realm);

            if (!token.hasAnyAudience(expectedAudiences)) {
                throw new RuntimeException("Token audience doesn't match domain. Expected audiences are any of " + expectedAudiences
                        + " but audience from token is '" + Arrays.asList(token.getAudience()) + "'");
            }

            validator.validateToken();
            // JWT-SVIDs don't have jti
//            validator.validateTokenReuse();

            // Not (yet) supported due to a regression in Keycloak; TBD
//            Map<String, String> config = ((AuthenticationFlowContext) context).getAuthenticatorConfig().getConfig();
//            String trustDomain = config.get(TRUST_DOMAIN);
//            String oidcIssuer = config.get(OIDC_ISSUER);
            validator.validateSPIFFE(trustDomain, oidcIssuer);

            context.success();
        } catch (RuntimeException | JWSInputException e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_CLIENT, "Client authentication with JWT-SVID failed: " + e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
        }

    }

    private List<String> getExpectedAudiences(ClientAuthenticationFlowContext context, RealmModel realm) {
        String issuerUrl = Urls.realmIssuer(context.getUriInfo().getBaseUri(), realm.getName());
        String tokenUrl = OIDCLoginProtocolService.tokenUrl(context.getUriInfo().getBaseUriBuilder()).build(realm.getName()).toString();
        List<String> expectedAudiences = new ArrayList<>(Arrays.asList(issuerUrl, tokenUrl));

        return expectedAudiences;
    }

    @Override
    public String getHelpText() {
        return "Validates client based on signed JWT-SVID issued by SPIFFE";
    }

    @Override
    public String getDisplayType() {
        return "SPIFFE JWT-SVID";
    }

    // Not supported due to regression in Keycloak; TBD
/*
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty trustDomainProperty = new ProviderConfigProperty();
        trustDomainProperty.setName(TRUST_DOMAIN);
        trustDomainProperty.setHelpText("SPIFFE Trust Domain");
        trustDomainProperty.setType(ProviderConfigProperty.STRING_TYPE);
        trustDomainProperty.setRequired(true);

        ProviderConfigProperty issuerProperty = new ProviderConfigProperty();
        issuerProperty.setName(OIDC_ISSUER);
        issuerProperty.setHelpText("OIDC Issuer");
        issuerProperty.setType(ProviderConfigProperty.STRING_TYPE);
        issuerProperty.setRequired(true);

        return List.of(trustDomainProperty, issuerProperty);
    }
*/

    @Override
    public boolean isConfigurable() {
        return false;
    }

}
