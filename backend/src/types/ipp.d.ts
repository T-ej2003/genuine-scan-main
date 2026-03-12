declare module "ipp" {
  export type IppMessage = Record<string, unknown> & {
    data?: Buffer;
  };

  export type IppResponse = Record<string, any>;

  export interface IppPrinter {
    execute(operation: string, message: IppMessage, callback: (error: Error | null, response: IppResponse) => void): void;
  }

  export function Printer(
    url: string,
    options?: {
      charset?: string;
      language?: string;
      uri?: string;
      version?: string;
    }
  ): IppPrinter;

  const exported: {
    Printer: typeof Printer;
  };

  export default exported;
}
