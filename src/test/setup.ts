import "@testing-library/jest-dom";

const createMemoryStorage = (): Storage => {
  const store = new Map<string, string>();

  return {
    get length() {
      return store.size;
    },
    clear: () => {
      store.clear();
    },
    getItem: (key: string) => store.get(String(key)) ?? null,
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    removeItem: (key: string) => {
      store.delete(String(key));
    },
    setItem: (key: string, value: string) => {
      store.set(String(key), String(value));
    },
  };
};

const ensureBrowserStorage = (storageName: "localStorage" | "sessionStorage") => {
  let storage: Storage | undefined;
  try {
    storage = window[storageName];
  } catch {
    storage = undefined;
  }

  if (typeof storage?.clear === "function") return;

  Object.defineProperty(window, storageName, {
    configurable: true,
    writable: true,
    value: createMemoryStorage(),
  });

  Object.defineProperty(globalThis, storageName, {
    configurable: true,
    writable: true,
    value: window[storageName],
  });
};

ensureBrowserStorage("localStorage");
ensureBrowserStorage("sessionStorage");

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});

class MockResizeObserver {
  constructor(_callback?: ResizeObserverCallback) {}

  observe(_target?: Element, _options?: ResizeObserverOptions) {}

  unobserve(_target?: Element) {}

  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  configurable: true,
  writable: true,
  value: MockResizeObserver,
});

Object.defineProperty(window, "ResizeObserver", {
  configurable: true,
  writable: true,
  value: MockResizeObserver,
});
