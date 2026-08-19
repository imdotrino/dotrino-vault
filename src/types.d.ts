declare module "*.vue" {
  const component: any;
  export default component;
}
declare module "virtual:pwa-register" {
  export function registerSW(options?: any): (reloadPage?: boolean) => Promise<void>;
  export const updateServiceWorker: (reloadPage?: boolean) => Promise<void>;
}
