import * as fs from "fs";
import * as path from "path";
import { describe, expect, it, vi } from "vitest";

import {
  getTrustedBuilds,
  toTrustedBuild,
  UnifiedAttestationRegistry,
} from "../unified-attestation-registry";

const FIXTURES = path.join(__dirname, "fixtures", "unified-attestation");
const readDevice = (slug: string) =>
  JSON.parse(fs.readFileSync(path.join(FIXTURES, `${slug}.json`), "utf-8"));

const algiz = readDevice("volla-algiz");
const ansuz = readDevice("volla-ansuz");
const VOLLA_OEM = "Volla OEM";
const BASE_URL = "https://registry.example";

// A device family of a trusted OEM which is attested by custom roots instead of the Google ones
const customRootDevice = {
  ...algiz,
  certificate: {
    ...algiz.certificate,
    authority: {
      name: "Custom",
      rootCertificatesUrl: "https://custom-authority.example/root",
    },
  },
  slug: "volla-custom",
};

const listItem = (slug: string, oemOrgName: null | string, enabled = true) => ({
  enabled,
  oemOrgName,
  slug,
});

const registryFetch = (
  routes: Record<string, unknown>,
): typeof fetch & { requested: string[] } => {
  const requested: string[] = [];
  const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
    const url = input.toString();
    requested.push(url);
    return url in routes
      ? new Response(JSON.stringify(routes[url]), { status: 200 })
      : new Response("not found", { status: 404 });
  });
  return Object.assign(fetchFn as unknown as typeof fetch, { requested });
};

const page = (n: number) => `${BASE_URL}/api/v1/devices?page=${n}&pageSize=100`;
const detail = (slug: string) => `${BASE_URL}/api/v1/devices/${slug}`;

const userBuilds = (device: typeof algiz): string[] =>
  device.builds
    .filter(({ buildFingerprint }: { buildFingerprint: string }) =>
      buildFingerprint.endsWith(":user/release-keys"),
    )
    .map(
      ({
        verifiedBootHashHex,
        verifiedBootKeyHex,
      }: {
        verifiedBootHashHex: string;
        verifiedBootKeyHex: string;
      }) => toTrustedBuild(verifiedBootKeyHex, verifiedBootHashHex),
    );

describe("getTrustedBuilds", () => {
  it("should trust only the user builds of a trusted OEM attested by the Google roots", () => {
    const builds = getTrustedBuilds(algiz, [VOLLA_OEM]);

    expect(builds).toEqual(userBuilds(algiz));
    expect(builds).toHaveLength(6);
    expect(builds).not.toContain(
      toTrustedBuild(
        "22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c",
        "4b4195ca70d8e88c0b766439556b74f99eca41170402ea872d0111978478df1d",
      ),
    );
  });

  it("should exclude the userdebug builds signed with another key", () => {
    const builds = getTrustedBuilds(ansuz, [VOLLA_OEM]);

    expect(builds).toHaveLength(9);
    expect(builds.some((build) => build.startsWith("7728e30f"))).toBe(false);
  });

  it.each([
    ["an untrusted OEM", algiz, ["Another OEM"]],
    ["custom roots", customRootDevice, [VOLLA_OEM]],
    ["a disabled device family", { ...algiz, enabled: false }, [VOLLA_OEM]],
    ["no trust anchor", { ...algiz, certificate: null }, [VOLLA_OEM]],
  ])("should trust no build of %s", (_, device, trustedOems) => {
    expect(getTrustedBuilds(device, trustedOems)).toEqual([]);
  });

  it("should skip the builds without verified boot hash", () => {
    const device = {
      ...algiz,
      builds: algiz.builds.map((build: object) => ({
        ...build,
        verifiedBootHashHex: null,
      })),
    };
    expect(getTrustedBuilds(device, [VOLLA_OEM])).toEqual([]);
  });
});

describe("UnifiedAttestationRegistry", () => {
  const routes = {
    [detail("volla-algiz")]: algiz,
    [detail("volla-ansuz")]: ansuz,
    [detail("volla-custom")]: customRootDevice,
    [page(1)]: {
      items: [
        listItem("volla-algiz", VOLLA_OEM),
        listItem("other-device", "Other OEM"),
        listItem("volla-disabled", VOLLA_OEM, false),
      ],
      totalPages: 2,
    },
    [page(2)]: {
      items: [
        listItem("volla-ansuz", VOLLA_OEM),
        listItem("volla-custom", VOLLA_OEM),
      ],
      totalPages: 2,
    },
  };

  it("should load the trusted builds of all the pages", async () => {
    const fetchFn = registryFetch(routes);
    const registry = new UnifiedAttestationRegistry({
      baseUrl: `${BASE_URL}/`,
      fetchFn,
      trustedOems: [VOLLA_OEM],
    });

    await registry.refresh();

    expect([...registry.getBuilds()].sort()).toEqual(
      [...userBuilds(algiz), ...userBuilds(ansuz)].sort(),
    );
    // The details of the untrusted or disabled device families are not requested
    expect(fetchFn.requested).toEqual([
      page(1),
      page(2),
      detail("volla-algiz"),
      detail("volla-ansuz"),
      detail("volla-custom"),
    ]);
  });

  it("should keep the trusted builds when a refresh fails", async () => {
    let currentFetch = registryFetch(routes);
    const registry = new UnifiedAttestationRegistry({
      baseUrl: BASE_URL,
      fetchFn: (input, init) => currentFetch(input, init),
      trustedOems: [VOLLA_OEM],
    });
    await registry.refresh();
    const builds = registry.getBuilds();
    expect(builds.size).toBe(15);

    currentFetch = registryFetch({ ...routes, [detail("volla-ansuz")]: {} });
    await expect(registry.refresh()).rejects.toThrow(
      "Invalid Unified Attestation device volla-ansuz",
    );
    expect(registry.getBuilds()).toBe(builds);

    currentFetch = registryFetch({});
    await expect(registry.refresh()).rejects.toThrow("404");
    expect(registry.getBuilds()).toBe(builds);
  });

  it("should trust no build until the first refresh succeeds", async () => {
    const registry = new UnifiedAttestationRegistry({
      baseUrl: BASE_URL,
      fetchFn: registryFetch({}),
      trustedOems: [VOLLA_OEM],
    });

    await expect(registry.refresh()).rejects.toThrow("404");
    expect(registry.getBuilds().size).toBe(0);
  });
});
