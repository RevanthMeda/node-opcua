import "mocha";

import { describeWithLeakDetector as describe } from "node-opcua-leak-detector";
import { SecurityPolicy } from "node-opcua-secure-channel";
import { UserTokenType } from "node-opcua-service-endpoints";
import { MessageSecurityMode } from "node-opcua-service-secure-channel";
import { AnonymousIdentityToken } from "node-opcua-service-session";
import should from "should";

import { OPCUAClient } from "../dist/index.js";

interface TokenAndSignature {
    userIdentityToken: AnonymousIdentityToken | null;
}

interface EndpointLike {
    securityMode: MessageSecurityMode;
    userIdentityTokens?: Array<{
        policyId: string;
        tokenType: UserTokenType;
        securityPolicyUri?: string;
    }>;
}

interface IdentityContext {
    endpoint: EndpointLike;
    securityPolicy: SecurityPolicy;
    serverCertificate: Buffer;
    serverNonce: Buffer;
}

interface InternalClient {
    createUserIdentityToken(
        context: IdentityContext,
        userIdentityInfo: { type: UserTokenType },
        callback: (err: Error | null, data?: TokenAndSignature) => void
    ): void;
}

function createAnonymousToken(endpoint: EndpointLike) {
    const client = OPCUAClient.create({}) as unknown as InternalClient;
    return new Promise<AnonymousIdentityToken>((resolve, reject) => {
        client.createUserIdentityToken(
            {
                endpoint,
                securityPolicy: SecurityPolicy.None,
                serverCertificate: Buffer.alloc(0),
                serverNonce: Buffer.alloc(0)
            },
            { type: UserTokenType.Anonymous },
            (err, data) => {
                if (err) {
                    reject(err);
                    return;
                }
                const token = data?.userIdentityToken;
                if (!(token instanceof AnonymousIdentityToken)) {
                    reject(new Error("Expected AnonymousIdentityToken"));
                    return;
                }
                resolve(token);
            }
        );
    });
}

describe("anonymous identity compatibility when endpoint token policies are missing", () => {
    it("should use an empty policyId on an unsecured endpoint with no advertised token policies", async () => {
        const token = await createAnonymousToken({
            securityMode: MessageSecurityMode.None,
            userIdentityTokens: []
        });

        token.policyId.should.eql("");
    });

    it("should still reject a secure endpoint with no advertised anonymous policy", async () => {
        await should(
            createAnonymousToken({
                securityMode: MessageSecurityMode.Sign,
                userIdentityTokens: []
            })
        ).be.rejectedWith(/Cannot find ANONYMOUS user token policy/);
    });

    it("should not infer anonymous when the endpoint advertises a different identity policy", async () => {
        await should(
            createAnonymousToken({
                securityMode: MessageSecurityMode.None,
                userIdentityTokens: [
                    {
                        policyId: "username",
                        tokenType: UserTokenType.UserName,
                        securityPolicyUri: SecurityPolicy.None
                    }
                ]
            })
        ).be.rejectedWith(/Cannot find ANONYMOUS user token policy/);
    });
});
