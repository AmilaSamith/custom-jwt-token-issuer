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

    @Override
    protected JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                             String consumerKey) throws IdentityOAuth2Exception {
        JWTClaimsSet jwtClaimsSet = super.createJWTClaimSet(authAuthzReqMessageContext, tokenReqMessageContext,
                consumerKey);
        String userId = getUserId();
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);
        jwtClaimsSetBuilder.subject(userId);
        return jwtClaimsSetBuilder.build();
    }

    public String getUserId() {
        return  UUID.randomUUID().toString();
    }
}
