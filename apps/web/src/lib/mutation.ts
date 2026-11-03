"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";

type Key = readonly unknown[];

/**
 * A mutation that invalidates the query keys it touched once it succeeds, so the thing
 * the person acted on updates in place. `keys` may depend on the result and variables.
 */
export function useInvalidating<TVars, TData>(
  mutationFn: (vars: TVars) => Promise<TData>,
  keys: Key[] | ((data: TData, vars: TVars) => Key[]),
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn,
    onSuccess: async (data, vars) => {
      const list = typeof keys === "function" ? keys(data, vars) : keys;
      await Promise.all(list.map((k) => client.invalidateQueries({ queryKey: k })));
    },
  });
}
