import { afterEach, expect, it } from "vitest";

import { queryClient } from "@/lib/query-client";
import { clearRequestCoordinator, setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

afterEach(() => {
  queryClient.clear();
  setRequestCoordinatorScope(null);
});

it("discards authenticated query data on actor changes but retains it on cache-only invalidation", () => {
  setRequestCoordinatorScope({ id: "actor-a" });
  queryClient.setQueryData(["private"], { value: "actor-a" });
  clearRequestCoordinator();
  expect(queryClient.getQueryData(["private"])).toEqual({ value: "actor-a" });
  setRequestCoordinatorScope({ id: "actor-b" });
  expect(queryClient.getQueryData(["private"])).toBeUndefined();
});
