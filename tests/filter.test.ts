import { describe, it, expect } from "vitest";
import { OpenCodeFilter } from "../src/index.js";

describe("OpenCodeFilter", () => {
  it("should create a filter instance", () => {
    const filter = new OpenCodeFilter();
    expect(filter).toBeDefined();
  });

  it("should process data with include rule", async () => {
    const filter = new OpenCodeFilter({
      rules: [
        {
          name: "positive-numbers",
          condition: (item) => typeof item === "number" && item > 0,
          action: "include",
        },
      ],
    });

    const data = [1, -1, 2, -2, 3, -3];
    const result = await filter.process(data);

    expect(result).toEqual([1, 2, 3]);
  });

  it("should process data with exclude rule", async () => {
    const filter = new OpenCodeFilter({
      rules: [
        {
          name: "exclude-negative",
          condition: (item) => typeof item === "number" && item < 0,
          action: "exclude",
        },
      ],
    });

    const data = [1, -1, 2, -2, 3, -3];
    const result = await filter.process(data);

    expect(result).toEqual([1, 2, 3]);
  });

  it("should add rules dynamically", () => {
    const filter = new OpenCodeFilter();
    filter.addRule({
      name: "test-rule",
      condition: () => true,
      action: "include",
    });

    // If no error thrown, test passes
    expect(true).toBe(true);
  });
});
