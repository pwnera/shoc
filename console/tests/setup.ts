import "@testing-library/jest-dom/vitest";

// jsdom has no ReadableStream pipeThrough for the SSE reader, and no matchMedia.
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }),
});
