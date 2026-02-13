type LocationLookupResult = {
    name: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
};
export declare const reverseGeocode: (lat?: number | null, lon?: number | null) => Promise<LocationLookupResult | null>;
export declare const locationLabelFromCoords: (lat?: number | null, lon?: number | null) => Promise<string | null>;
export declare const compactDeviceLabel: (raw?: string | null) => string | null;
export {};
//# sourceMappingURL=locationService.d.ts.map