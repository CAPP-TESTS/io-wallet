import { NonEmptyString } from "@pagopa/ts-commons/lib/strings";
import { createHash, createSign } from "crypto";
import * as E from "fp-ts/Either";
import * as TE from "fp-ts/TaskEither";
import { AndroidDeviceDetails } from "io-wallet-common/device-details";
import { JwkPublicKey } from "io-wallet-common/jwk";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { emitTelemetryCustomEvent } from "@/infra/telemetry";

import { AndroidAssertionParams, validateAndroidAssertion } from "..";
import { GoogleAppCredentials } from "../assertion";
import { verifyAttestation } from "../attestation";
import { toTrustedBuild } from "../unified-attestation-registry";
import {
  createAttestation,
  createTestRoot,
  GRAPHENEOS_BOOT_KEY,
  grapheneOsParams,
  PACKAGE_NAME,
  SIGNATURE_DIGEST,
  TestAttestationParams,
  TestRoot,
} from "./key-attestation-chain";

vi.mock("@/infra/telemetry", () => ({
  emitTelemetryCustomEvent: vi.fn(),
}));

vi.mock("@/certificates", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/certificates")>()),
  getCrlFromUrl: () => TE.right({ entries: {} }),
}));

// Volla OS verified boot key and the hashes of a user and a userdebug build of the Volla Phone Quintus,
// from the Unified Attestation registry (fixtures/unified-attestation/volla-algiz.json)
const VOLLA_BOOT_KEY =
  "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c";
const VOLLA_USER_BUILD_HASH =
  "723d9c54a3f592daad65c965cbef66b323f5be79d251198a890fe639976cb203";
const VOLLA_USERDEBUG_BUILD_HASH =
  "4b4195ca70d8e88c0b766439556b74f99eca41170402ea872d0111978478df1d";

const trustedSelfSignedBootKeys = new Set([GRAPHENEOS_BOOT_KEY]);
const trustedSelfSignedBuilds = new Set([
  toTrustedBuild(VOLLA_BOOT_KEY, VOLLA_USER_BUILD_HASH),
]);

const vollaParams = (overrides: Partial<TestAttestationParams> = {}) =>
  grapheneOsParams({
    verifiedBootHash: VOLLA_USER_BUILD_HASH,
    verifiedBootKey: VOLLA_BOOT_KEY,
    ...overrides,
  });

describe("Volla OS key attestation through the Unified Attestation registry", () => {
  let root: TestRoot;

  beforeAll(async () => {
    root = await createTestRoot();
  });

  const verify = async (
    params: TestAttestationParams,
    options: Parameters<typeof createAttestation>[2] = {},
  ) => {
    const { x509Chain } = await createAttestation(root, params, options);
    return verifyAttestation({
      attestationCrl: { entries: {} },
      attestKey: { requiredForSelfSigned: true },
      bundleIdentifiers: [PACKAGE_NAME],
      challenge: params.challenge,
      googlePublicKeys: [root.publicKeyPem],
      signatureDigests: [SIGNATURE_DIGEST],
      trustedSelfSignedBootKeys,
      trustedSelfSignedBuilds,
      x509Chain,
    });
  };

  it("should accept a locked device running a trusted user build and pin its attest key", async () => {
    const result = await verify(vollaParams());

    expect(result).toMatchObject({
      deviceDetails: {
        attestKey: expect.objectContaining({ kty: "EC" }),
        deviceLocked: true,
        verifiedBootKey: VOLLA_BOOT_KEY,
        verifiedBootState: 1,
      },
      success: true,
    });
  });

  it.each([
    [
      "a userdebug build signed with the same key",
      vollaParams({ verifiedBootHash: VOLLA_USERDEBUG_BUILD_HASH }),
      "VerifiedBootKey of the self-signed OS is not allowed",
    ],
    [
      "a build which is not registered",
      vollaParams({ verifiedBootHash: "cd".repeat(32) }),
      "VerifiedBootKey of the self-signed OS is not allowed",
    ],
    [
      "a registered build hash with another verified boot key",
      vollaParams({ verifiedBootKey: "ef".repeat(32) }),
      "VerifiedBootKey of the self-signed OS is not allowed",
    ],
    [
      "an app re-signed with another certificate",
      vollaParams({ signatureDigests: ["cd".repeat(32)] }),
      "The app signing certificate does not match",
    ],
  ])("should reject %s", async (_, params, reason) => {
    const result = await verify(params);

    expect(result).toMatchObject({
      reason: expect.stringContaining(reason),
      success: false,
    });
  });

  it("should require an attest key", async () => {
    const result = await verify(vollaParams(), { attestKey: null });

    expect(result).toMatchObject({
      reason: expect.stringContaining(
        "An attest key is required for a self-signed OS",
      ),
      success: false,
    });
  });
});

describe("Volla OS assertion with key attestation fallback", () => {
  let root: TestRoot;

  beforeAll(async () => {
    root = await createTestRoot();
  });

  beforeEach(() => {
    vi.mocked(emitTelemetryCustomEvent).mockClear();
  });

  const clientData = JSON.stringify({ challenge: "volla-challenge" });
  const requestHash = createHash("sha256").update(clientData).digest("hex");

  /**
   * Registers a Volla device and prepares an assertion with a fresh key attestation of the given build.
   */
  const setup = async (
    freshBuildHash: string,
  ): Promise<AndroidAssertionParams> => {
    const registration = await createAttestation(root, vollaParams());
    const verified = await verifyAttestation({
      attestationCrl: { entries: {} },
      attestKey: { requiredForSelfSigned: true },
      bundleIdentifiers: [PACKAGE_NAME],
      challenge: "challenge",
      googlePublicKeys: [root.publicKeyPem],
      signatureDigests: [SIGNATURE_DIGEST],
      trustedSelfSignedBootKeys,
      trustedSelfSignedBuilds,
      x509Chain: registration.x509Chain,
    });
    if (!verified.success) {
      throw new Error(verified.reason);
    }
    const fresh = await createAttestation(
      root,
      vollaParams({ challenge: requestHash, verifiedBootHash: freshBuildHash }),
      { attestKey: registration.attestKey },
    );
    return {
      allowDevelopmentEnvironment: false,
      androidPlayIntegrityUrl: "",
      androidPlayStoreCertificateHash: "",
      bundleIdentifiers: [PACKAGE_NAME],
      clientData,
      deviceDetails: verified.deviceDetails as AndroidDeviceDetails,
      googleAppCredentials: {} as GoogleAppCredentials,
      hardwareKey: verified.hardwareKey as JwkPublicKey,
      hardwareKeyAttestation: fresh.encoded as NonEmptyString,
      hardwareSignature: createSign("SHA256")
        .update(clientData)
        .sign(registration.privateKey, "base64") as NonEmptyString,
      keyAttestationConfig: {
        androidCrlUrl: "",
        googlePublicKeys: [root.publicKeyPem],
        httpRequestTimeout: 1,
        signatureDigests: [SIGNATURE_DIGEST],
        trustedSelfSignedBootKeys,
        trustedSelfSignedBuilds,
      },
    };
  };

  it("should accept a fresh key attestation of a trusted user build", async () => {
    const result = await validateAndroidAssertion(
      await setup(VOLLA_USER_BUILD_HASH),
    )();

    expect(result).toEqual(E.right(undefined));
    expect(emitTelemetryCustomEvent).toHaveBeenCalledWith({
      name: "ANDROID_INTEGRITY_FALLBACK_SUCCEEDED",
      properties: { os: "unified_attestation", playIntegrity: "missing" },
    });
  });

  it("should reject a fresh key attestation of a userdebug build", async () => {
    const result = await validateAndroidAssertion(
      await setup(VOLLA_USERDEBUG_BUILD_HASH),
    )();

    expect(E.isLeft(result) && result.left.message).toContain(
      "VerifiedBootKey of the self-signed OS is not allowed",
    );
    expect(emitTelemetryCustomEvent).not.toHaveBeenCalled();
  });
});
