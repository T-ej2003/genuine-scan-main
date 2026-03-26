import {
  INDUSTRIAL_PRINTER_MODEL_CATALOG,
  type IndustrialPrinterCatalogEntry,
} from "./fixtures/industrialPrinterSourceData";

const normalize = (value: unknown) => String(value || "").trim().toLowerCase();

export type CatalogEntry = IndustrialPrinterCatalogEntry;

export { INDUSTRIAL_PRINTER_MODEL_CATALOG };

export const matchPrinterCatalogEntry = (params: {
  brand?: string | null;
  vendor?: string | null;
  model?: string | null;
  name?: string | null;
}) => {
  const brand = normalize(params.brand || params.vendor);
  const model = normalize(params.model);
  const name = normalize(params.name);

  return (
    INDUSTRIAL_PRINTER_MODEL_CATALOG.find((entry) => {
      if (brand && normalize(entry.brand) !== brand) return false;
      return entry.representativeModels.some((candidate: string) => {
        const token = normalize(candidate);
        return model.includes(token) || name.includes(token);
      });
    }) ||
    INDUSTRIAL_PRINTER_MODEL_CATALOG.find((entry) => {
      const entryBrand = normalize(entry.brand);
      return Boolean(entryBrand) && (model.includes(entryBrand) || name.includes(entryBrand) || brand === entryBrand);
    }) ||
    null
  );
};
