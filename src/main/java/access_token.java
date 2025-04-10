// Java translation of the Go OAuth token processor using Gin and post-quantum signing

package processor;

import com.coranlabs.coran_lib_openapi.models.*;
import com.coranlabs.coran_lib_util.mapstruct.MapStruct;
import com.coranlabs.coran_lib_util.mongoapi.MongoAPI;
import com.coranlabs.coran_nrf.application_entity.logger.Logger;
import com.coranlabs.coran_nrf.application_entity.util.Util;
import com.coranlabs.coran_nrf.messages_handling_entity.context.NrfContext;
import com.lakshya_chopra.jwt.*;
import com.lakshya_chopra.jwt.pq.Ed448MLDSA87;
import com.mongodb.client.model.Filters;
import org.bson.conversions.Bson;

import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.*;

public class Processor {
    public void handleAccessTokenRequest(HttpServletResponse response, AccessTokenReq accessTokenReq) {
        Logger.accTokenLog.debug("Handle AccessTokenRequest");

        Object[] result = accessTokenProcedure(accessTokenReq);
        AccessTokenRsp tokenRsp = (AccessTokenRsp) result[0];
        AccessTokenErr tokenErr = (AccessTokenErr) result[1];

        try {
            if (tokenErr != null) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write(Util.toJson(tokenErr));
            } else if (tokenRsp != null) {
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(Util.toJson(tokenRsp));
            } else {
                Logger.accTokenLog.error("AccessTokenProcedure returned neither an error nor a response");
                ProblemDetails problemDetails = new ProblemDetails();
                problemDetails.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                problemDetails.setCause("UNSPECIFIED");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write(Util.toJson(problemDetails));
            }
        } catch (Exception e) {
            Logger.accTokenLog.error("Exception in handleAccessTokenRequest: " + e.getMessage());
        }
    }

    public Object[] accessTokenProcedure(AccessTokenReq request) {
        Logger.accTokenLog.debug("In AccessTokenProcedure");

        int expiration = 1000;
        String tokenType = "Bearer";
        String scope = request.getScope();
        Instant now = Instant.now();
        int nowNum = (int) now.getEpochSecond();

        AccessTokenErr errResponse = accessTokenScopeCheck(request);
        if (errResponse != null) {
            Logger.accTokenLog.error("AccessTokenScopeCheck error: " + errResponse.getError());
            return new Object[]{null, errResponse};
        }

        NrfContext nrfCtx = NrfContext.getSelf();
        AccessTokenClaims claims = new AccessTokenClaims();
        claims.setIss(nrfCtx.getNrfNfInstanceID());
        claims.setSub(request.getNfInstanceId());
        claims.setAud(request.getTargetNfInstanceId());
        claims.setScope(scope);
        claims.setExp(nowNum + expiration);
        claims.setIssuedAt(new NumericDate(now));

        Jwt token = new Jwt(new Ed448MLDSA87(), claims);
        String accessToken;
        try {
            accessToken = token.sign(nrfCtx.getNrfPrivKey());
        } catch (Exception e) {
            Logger.accTokenLog.warn("Signed string error: " + e.getMessage());
            return new Object[]{null, new AccessTokenErr("invalid_request")};
        }

        Logger.accTokenLog.info("Signed the access token with Ed448-MLDSA87");

        AccessTokenRsp response = new AccessTokenRsp();
        response.setAccessToken(accessToken);
        response.setTokenType(tokenType);
        response.setExpiresIn(expiration);
        response.setScope(scope);

        return new Object[]{response, null};
    }

    public AccessTokenErr accessTokenScopeCheck(AccessTokenReq req) {
        String collName = NrfContext.NF_PROFILE_COLL_NAME;

        if (!"client_credentials".equals(req.getGrantType())) {
            return new AccessTokenErr("unsupported_grant_type");
        }

        String reqNfType = req.getNfType().toUpperCase();
        String reqTargetNfType = req.getTargetNfType().toUpperCase();
        String reqNfInstanceId = req.getNfInstanceId();

        if (reqNfType.isEmpty() || reqTargetNfType.isEmpty() || reqNfInstanceId.isEmpty()) {
            return new AccessTokenErr("invalid_request");
        }

        Logger.accTokenLog.debug("reqNfInstanceId: " + reqNfInstanceId);

        Bson filter = Filters.eq("nfInstanceId", reqNfInstanceId);
        Map<String, Object> consumerNfInfo = MongoAPI.restfulAPIGetOne(collName, filter);
        if (consumerNfInfo == null) {
            Logger.accTokenLog.error("MongoAPI get consumer NF error");
            return new AccessTokenErr("invalid_client");
        }

        NfProfile nfProfile = new NfProfile();
        MapStruct.decode(consumerNfInfo, nfProfile);

        if (!nfProfile.getNfType().toUpperCase().equals(reqNfType)) {
            return new AccessTokenErr("invalid_client");
        }

        if (reqTargetNfType.equals("NRF")) {
            return null;
        }

        filter = Filters.eq("nfType", reqTargetNfType);
        Map<String, Object> producerNfInfo = MongoAPI.restfulAPIGetOne(collName, filter);
        if (producerNfInfo == null || producerNfInfo.isEmpty()) {
            Logger.accTokenLog.error("No producer info for targetNfType: " + reqTargetNfType);
            return new AccessTokenErr("invalid_client");
        }

        MapStruct.decode(producerNfInfo, nfProfile);
        List<NfService> nfServices = nfProfile.getNfServices();

        for (String reqService : req.getScope().split(" ")) {
            boolean found = false;
            for (NfService nfService : nfServices) {
                if (nfService.getServiceName().equals(reqService)) {
                    List<String> allowedTypes = nfService.getAllowedNfTypes();
                    if (allowedTypes == null || allowedTypes.isEmpty() || allowedTypes.contains(reqNfType)) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                Logger.accTokenLog.error("Scope out of bounds: " + reqService);
                return new AccessTokenErr("invalid_scope");
            }
        }
        return null;
    }
}
