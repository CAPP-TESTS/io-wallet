import * as E from "fp-ts/Either";
import { pipe } from "fp-ts/function";
import * as t from "io-ts";
import { PathReporter } from "io-ts/PathReporter";

/**
 * Roots of the Google attestation authority, the only ones trusted to verify key attestation chains:
 * the devices registered with another authority (e.g. custom OEM roots) are ignored.
 */
export const GOOGLE_ROOT_CERTIFICATES_URL =
  "https://android.googleapis.com/attestation/root";

/**
 * Only the builds for production devices are trusted: userdebug and eng builds expose debugging
 * features, while sharing the verified boot key of the user builds.
 */
const USER_BUILD_FINGERPRINT = /:user\/release-keys$/;

const Hex256 = t.refinement(t.string, (value) =>
  /^[0-9a-fA-F]{64}$/.test(value),
);

const DeviceList = t.type({
  items: t.array(
    t.type({
      enabled: t.boolean,
      oemOrgName: t.union([t.string, t.null]),
      slug: t.string,
    }),
  ),
  totalPages: t.number,
});

const DeviceDetail = t.type({
  builds: t.array(
    t.type({
      buildFingerprint: t.string,
      verifiedBootHashHex: t.union([t.string, t.null]),
      verifiedBootKeyHex: t.string,
    }),
  ),
  certificate: t.union([
    t.type({
      authority: t.type({ rootCertificatesUrl: t.string }),
    }),
    t.null,
  ]),
  enabled: t.boolean,
  oemOrgName: t.union([t.string, t.null]),
  slug: t.string,
});

type DeviceDetail = t.TypeOf<typeof DeviceDetail>;

/**
 * Identifies a trusted build by its verified boot key and verified boot hash, as reported by the
 * root of trust of a key attestation (hex encoded).
 * @param verifiedBootKey - The verified boot key.
 * @param verifiedBootHash - The verified boot hash.
 * @returns the identifier of the build.
 */
export const toTrustedBuild = (
  verifiedBootKey: string,
  verifiedBootHash: string,
) => `${verifiedBootKey.toLowerCase()}:${verifiedBootHash.toLowerCase()}`;

const decode = <A>(
  codec: t.Decoder<unknown, A>,
  value: unknown,
  what: string,
) =>
  pipe(
    codec.decode(value),
    E.getOrElseW((errors) => {
      throw new Error(
        `Invalid Unified Attestation ${what}: ${PathReporter.report(E.left(errors)).join(", ")}`,
      );
    }),
  );

/**
 * Extracts the trusted builds of a device family of the registry.
 * @param device - The device family detail.
 * @param trustedOems - The names of the trusted OEM organizations.
 * @returns the identifiers of the trusted builds, see {@link toTrustedBuild}.
 */
export const getTrustedBuilds = (
  device: DeviceDetail,
  trustedOems: readonly string[],
): string[] =>
  device.enabled &&
  device.oemOrgName !== null &&
  trustedOems.includes(device.oemOrgName) &&
  device.certificate?.authority.rootCertificatesUrl ===
    GOOGLE_ROOT_CERTIFICATES_URL
    ? device.builds.flatMap(
        ({ buildFingerprint, verifiedBootHashHex, verifiedBootKeyHex }) =>
          USER_BUILD_FINGERPRINT.test(buildFingerprint) &&
          Hex256.is(verifiedBootKeyHex) &&
          Hex256.is(verifiedBootHashHex)
            ? [toTrustedBuild(verifiedBootKeyHex, verifiedBootHashHex)]
            : [],
      )
    : [];

export interface UnifiedAttestationRegistryOptions {
  /** Base URL of the Unified Attestation backend, e.g. https://backend.example. */
  baseUrl: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  /** Names of the trusted OEM organizations, e.g. "Volla OEM". */
  trustedOems: readonly string[];
}

/**
 * Provider of the builds of an OS signed with a custom verified boot key, registered by trusted OEMs
 * in the public device registry of a Unified Attestation backend (https://uattest.net). They extend
 * the GrapheneOS verified boot keys for devices with a locked bootloader running such an OS.
 * A build is trusted when its device family:
 * - is registered by one of the trusted OEM organizations;
 * - is attested by the Google attestation roots, the only ones trusted by the Wallet Provider;
 * and the build is a user build with both its verified boot key and hash, so that the key attestation
 * pins the exact build. On any failure the last accepted builds are kept, it never fails open.
 */
export class UnifiedAttestationRegistry {
  private builds: ReadonlySet<string> = new Set();

  constructor(private readonly options: UnifiedAttestationRegistryOptions) {}

  /**
   * @returns the trusted builds, see {@link toTrustedBuild}.
   */
  getBuilds(): ReadonlySet<string> {
    return this.builds;
  }

  /**
   * Downloads the device families of the trusted OEMs and applies their trusted builds.
   * @throws {Error} - If any download or response is not valid, the current builds are kept.
   */
  async refresh() {
    const slugs: string[] = [];
    for (let page = 1, totalPages = 1; page <= totalPages; page++) {
      const list = decode(
        DeviceList,
        await this.get(`/api/v1/devices?page=${page}&pageSize=100`),
        "device list",
      );
      totalPages = list.totalPages;
      slugs.push(
        ...list.items
          .filter(
            ({ enabled, oemOrgName }) =>
              enabled &&
              oemOrgName !== null &&
              this.options.trustedOems.includes(oemOrgName),
          )
          .map(({ slug }) => slug),
      );
    }
    const builds = new Set<string>();
    for (const slug of slugs) {
      const device = decode(
        DeviceDetail,
        await this.get(`/api/v1/devices/${encodeURIComponent(slug)}`),
        `device ${slug}`,
      );
      getTrustedBuilds(device, this.options.trustedOems).forEach((build) =>
        builds.add(build),
      );
    }
    this.builds = builds;
  }

  /**
   * Refreshes the builds now and then periodically, logging failures.
   * @param intervalMs - The refresh interval, 1 hour by default as new builds are registered with each release.
   * @returns the interval timer.
   */
  startAutoRefresh(intervalMs = 60 * 60 * 1000) {
    const refresh = () =>
      this.refresh().catch((e) =>
        console.warn(
          `[Unified Attestation registry] refresh failed, keeping ${this.builds.size} trusted builds: ${e}`,
        ),
      );
    refresh();
    return setInterval(refresh, intervalMs).unref();
  }

  private async get(path: string): Promise<unknown> {
    const fetchFn = this.options.fetchFn ?? fetch;
    const url = `${this.options.baseUrl.replace(/\/+$/, "")}${path}`;
    const res = await fetchFn(url, {
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 10000),
    });
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
    return res.json();
  }
}
