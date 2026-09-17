declare module "proxy-addr" {
  const proxyaddr: {
    compile(values: string[]): (address: string) => boolean;
  };
  export default proxyaddr;
}
