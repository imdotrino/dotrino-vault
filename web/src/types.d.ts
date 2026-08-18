declare module "*.vue" {
  const component: any;
  export default component;
}
declare module "virtual:pwa-register" {
  export function registerSW(options?: any): (reloadPage?: boolean) => Promise<void>;
  export const updateServiceWorker: (reloadPage?: boolean) => Promise<void>;
}
interface Element { [key: string]: any; }
interface EventTarget { [key: string]: any; }
interface HTMLElement { [key: string]: any; }
interface Event { [key: string]: any; }
interface Window { [key: string]: any; }
