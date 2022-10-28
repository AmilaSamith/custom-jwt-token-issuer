package org.example.issuer;

import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;

import java.util.UUID;

public class CustomJWTTokenIssuer extends JWTTokenIssuer{
    public CustomJWTTokenIssuer() throws IdentityOAuth2Exception {
        super();
    }

    /**
     * Method to customize claim values.
     */
    @Override
    protected JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                             String consumerKey) throws IdentityOAuth2Exception {
        // Obtain current claim set
        JWTClaimsSet jwtClaimsSet = super.createJWTClaimSet(authAuthzReqMessageContext, tokenReqMessageContext,
                consumerKey);
        // get new claim value (Eg: userId)
        String userId = getUserId();
        // initialize a builder with current claims.
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
        // change desired claim value (Eg: SUBJECT)
        jwtClaimsSetBuilder.subject(userId);

        return jwtClaimsSetBuilder.build();
    }

    /**
     * Method to get userID.
     *
     * INSTRUCTIONS:
     * You can change the implementation to obtain userID based on username
     * by passing username as a parameter.
     */
    public String getUserId() {
        return  UUID.randomUUID().toString();
    }
}
