import "@testing-library/jest-dom";

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
